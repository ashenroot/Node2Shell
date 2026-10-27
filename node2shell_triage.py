#!/usr/bin/env python3
"""
CVE-2026-111497 (Node2Shell) — Passive Triage Scanner
Authorized Engagement Use Only

Purpose:
  Sweep a list of targets using ONLY passive, zero-risk HTTP requests to
  identify systems that are candidates for CVE-2026-111497 exposure.
  No payloads. No crashes. No behavioral probing.

  Output is a prioritized candidate list:
    CONFIRMED_VULNERABLE  — version string found, < fixed threshold
    CONFIRMED_PATCHED     — version string found, >= fixed threshold
    LIKELY_NODE           — strong Node.js signals, version not disclosed
    POSSIBLE_NODE         — weaker signals (Brotli, Express patterns, etc.)
    UNLIKELY              — no meaningful Node.js indicators

  Hand CONFIRMED_VULNERABLE and LIKELY_NODE to the customer for credentialed
  scanning or controlled testing in their environment.

Signals collected (all passive):
  - Node.js / Express version strings in response headers
  - Version disclosure endpoints (/version, /health, etc.)
  - 404 error page content (dev-mode stack traces often include Node version)
  - Brotli response encoding active (Content-Encoding: br)
  - Express / Node.js header patterns (X-Powered-By, ETag format, cookies)
  - Cookie names (connect.sid = Express session middleware)
  - HTML body hints (webpack bundles, npm package references)

Usage:
  Single target:
    python3 node2shell_triage.py https://target.example.com

  Bulk from file (one URL/host per line):
    python3 node2shell_triage.py --input targets.txt --workers 10

  Output to JSON for reporting:
    python3 node2shell_triage.py --input targets.txt --json results.json

  Output to CSV:
    python3 node2shell_triage.py --input targets.txt --csv results.csv

  Filter by minimum score (version-confirmed results always pass):
    python3 node2shell_triage.py --input targets.txt --min-score 30

  Filter output to specific buckets only:
    python3 node2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_NODE
"""

import socket
import ssl
import sys
import re
import time
import json
import csv
import argparse
import threading
import queue
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Fixed thresholds
# ---------------------------------------------------------------------------
FIXED_VERSIONS = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
EOL_LINES = {18, 20, 21, 23, 25}

VERSION_PATHS = [
    "/version", "/_version", "/__version",
    "/api/version", "/api/v1/version", "/api/v2/version",
    "/health", "/__health", "/healthz", "/health/live", "/health/ready",
    "/status", "/api/status", "/info", "/api/info",
    "/metrics", "/ping", "/api/ping",
    "/actuator/info", "/actuator/health",
]

# Patterns that signal Node.js presence or version
NODE_VERSION_PATTERNS = [
    r'[Nn]ode(?:\.?[Jj][Ss])?[/\s:"\']+v?(\d+\.\d+\.\d+)',
    r'"node(?:js)?"\s*:\s*"v?(\d+\.\d+\.\d+)"',
    r'node/(\d+\.\d+\.\d+)',
    r'"runtime"\s*:\s*"[Nn]ode.*?(\d+\.\d+\.\d+)"',
    r'process\.version[^"\']*["\']v?(\d+\.\d+\.\d+)',
]

NODE_PRESENCE_PATTERNS = [
    r'[Ee]xpress',
    r'[Nn]ode(?:\.?[Jj][Ss])',
    r'npm',
    r'webpack',
    r'__webpack_require__',
    r'node_modules',
    r'[Ff]astify',
    r'[Kk]oa(?:\s|/)',
    r'[Nn]est(?:JS|\.js)',
    r'[Nn]ext(?:JS|\.js)',
    r'[Nn]uxt(?:\.js)?',
]

# Scoring weights
SIGNAL_SCORES = {
    "express_header":     40,
    "node_header":        30,
    "connect_sid_cookie": 20,
    "brotli_response":    15,
    "express_etag":       15,
    "body_node_presence": 10,
    "interesting_paths":   5,
}

LIKELY_THRESHOLD   = 40
POSSIBLE_THRESHOLD = 10

# ---------------------------------------------------------------------------
# Colors / output
# ---------------------------------------------------------------------------
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
B="\033[94m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BUCKET_DISPLAY = {
    "CONFIRMED_VULNERABLE": f"{R}{BOLD}CONFIRMED VULNERABLE{RESET}",
    "CONFIRMED_PATCHED":    f"{G}CONFIRMED PATCHED   {RESET}",
    "LIKELY_NODE":          f"{Y}LIKELY NODE         {RESET}",
    "POSSIBLE_NODE":        f"{B}POSSIBLE NODE       {RESET}",
    "UNLIKELY":             f"{DIM}UNLIKELY            {RESET}",
    "ERROR":                f"{DIM}ERROR               {RESET}",
}

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _make_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

_tls_ctx = _make_context()


def http_get(host, port, use_tls, path, timeout=8, method="GET"):
    """Returns (status_code, headers_dict, body_bytes, latency_ms, error)."""
    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Accept: */*\r\n"
        f"Accept-Encoding: gzip, deflate, br\r\n"
        f"Connection: close\r\n"
        f"User-Agent: node2shell-triage/1.0 (CVE-2026-111497 passive scan)\r\n"
        f"\r\n"
    ).encode()
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            sock = _tls_ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(req)
        buf = b""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 512 * 1024:   # 512 KB cap
                break
        sock.close()
        lat = int((time.monotonic() - t0) * 1000)
        sep = buf.find(b"\r\n\r\n")
        if sep == -1:
            return None, {}, buf, lat, None
        hlines = buf[:sep].decode("utf-8", errors="replace").split("\r\n")
        status_str = hlines[0]
        try:
            code = int(status_str.split()[1])
        except (IndexError, ValueError):
            code = None
        hdrs = {}
        for ln in hlines[1:]:
            if ":" in ln:
                k, _, v = ln.partition(":")
                hdrs[k.strip().lower()] = v.strip()
        body = buf[sep + 4:]
        return code, hdrs, body, lat, None
    except socket.timeout:
        return None, {}, b"", int((time.monotonic() - t0) * 1000), "timeout"
    except ConnectionRefusedError:
        return None, {}, b"", int((time.monotonic() - t0) * 1000), "refused"
    except Exception as e:
        return None, {}, b"", int((time.monotonic() - t0) * 1000), str(e)


def parse_version(s):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', s)
    return tuple(int(x) for x in m.groups()) if m else None


def version_verdict(vt):
    major = vt[0]
    if major in EOL_LINES or major < min(FIXED_VERSIONS):
        return "CONFIRMED_VULNERABLE", f"EOL v{'.'.join(str(x) for x in vt)} — no fix"
    if major in FIXED_VERSIONS:
        fv = FIXED_VERSIONS[major]
        fvs = ".".join(str(x) for x in fv)
        vs = ".".join(str(x) for x in vt)
        if vt < fv:
            return "CONFIRMED_VULNERABLE", f"v{vs} < {fvs}"
        return "CONFIRMED_PATCHED", f"v{vs} >= {fvs}"
    return "LIKELY_NODE", f"v{'.'.join(str(x) for x in vt)} (unknown release line)"


# ---------------------------------------------------------------------------
# Signal collection
# ---------------------------------------------------------------------------

def collect_signals(host, port, use_tls, timeout):
    """
    Runs all passive probes against a single target.
    Returns a dict of collected signals.
    """
    signals = {
        "node_version":          None,   # (major, minor, patch) tuple
        "version_source":        None,   # description of where version came from
        "brotli_response":       False,  # server sends Content-Encoding: br
        "express_header":        False,  # X-Powered-By contains Express
        "node_header":           False,  # any header contains "node" or version
        "express_etag":          False,  # weak ETag in Express format W/"..."
        "connect_sid_cookie":    False,  # connect.sid session cookie (Express)
        "body_node_presence":    False,  # Node.js indicators in response body
        "body_node_version":     None,   # version found in body
        "disclosure_path":       None,   # path where version was disclosed
        "raw_headers_sample":    {},     # first few interesting headers
        "interesting_paths":     [],     # non-404 paths found during sweep
        "latency_ms":            None,
        "http_status":           None,
        "error":                 None,
    }

    # --- Base GET ---
    code, hdrs, body, lat, err = http_get(host, port, use_tls, "/", timeout=timeout)
    signals["latency_ms"] = lat
    signals["http_status"] = code

    if err:
        signals["error"] = err
        return signals

    # Interesting headers
    for h in ("x-powered-by", "server", "via", "x-runtime", "x-generator",
              "x-node-version", "etag", "set-cookie"):
        if h in hdrs:
            signals["raw_headers_sample"][h] = hdrs[h][:120]

    # Brotli response
    if "br" in hdrs.get("content-encoding", ""):
        signals["brotli_response"] = True

    # Express / Node.js header signals
    xpb = hdrs.get("x-powered-by", "").lower()
    if "express" in xpb:
        signals["express_header"] = True
    if "node" in xpb or "node" in hdrs.get("server", "").lower():
        signals["node_header"] = True

    # Weak ETag format used by Express: W/"<hex>"
    etag = hdrs.get("etag", "")
    if re.match(r'^W/"[0-9a-f]+"$', etag):
        signals["express_etag"] = True

    # connect.sid cookie = Express-session
    cookie = hdrs.get("set-cookie", "")
    if "connect.sid" in cookie:
        signals["connect_sid_cookie"] = True

    # Version from base path headers
    for pat in NODE_VERSION_PATTERNS:
        for h_val in hdrs.values():
            m = re.search(pat, h_val, re.IGNORECASE)
            if m:
                v = parse_version(m.group(1))
                if v:
                    signals["node_version"] = v
                    signals["version_source"] = "GET / headers"
                    break
        if signals["node_version"]:
            break

    # Version from base path body (first 16 KB)
    body_text = body[:16384].decode("utf-8", errors="replace")
    if not signals["node_version"]:
        for pat in NODE_VERSION_PATTERNS:
            m = re.search(pat, body_text, re.IGNORECASE)
            if m:
                v = parse_version(m.group(1))
                if v:
                    signals["node_version"] = v
                    signals["version_source"] = "GET / body"
                    break

    # Node.js presence signals in body
    if not signals["node_version"]:
        for pat in NODE_PRESENCE_PATTERNS:
            if re.search(pat, body_text):
                signals["body_node_presence"] = True
                break

    # --- 404 probe (dev-mode error pages often expose version) ---
    if not signals["node_version"]:
        c404, h404, b404, _, e404 = http_get(
            host, port, use_tls, "/probe-triage-xyzzy-404", timeout=timeout)
        if not e404 and b404:
            b404_text = b404[:16384].decode("utf-8", errors="replace")
            for pat in NODE_VERSION_PATTERNS:
                m = re.search(pat, b404_text, re.IGNORECASE)
                if m:
                    v = parse_version(m.group(1))
                    if v:
                        signals["node_version"] = v
                        signals["version_source"] = "404 error page (dev mode)"
                        break
            if not signals["node_version"]:
                for pat in NODE_PRESENCE_PATTERNS:
                    if re.search(pat, b404_text):
                        signals["body_node_presence"] = True
                        break
                # Also check for Express default 404 text
                if "cannot get" in b404_text.lower() or "not found" in b404_text.lower():
                    if "express" in b404_text.lower() or "express" in h404.get("x-powered-by", "").lower():
                        signals["express_header"] = True

    # --- Version path sweep ---
    if not signals["node_version"]:
        for vpath in VERSION_PATHS:
            vc, vh, vb, _, ve = http_get(
                host, port, use_tls, vpath,
                timeout=max(3, timeout // 2))
            if ve or vc in (404, 403, 405, None):
                continue
            # Interesting path found
            signals["interesting_paths"].append(f"{vpath} ({vc})")
            vb_text = vb[:8192].decode("utf-8", errors="replace")
            # Try version extraction
            for pat in NODE_VERSION_PATTERNS:
                m_h = None
                for hv in vh.values():
                    m_h = re.search(pat, hv, re.IGNORECASE)
                    if m_h:
                        break
                m_b = re.search(pat, vb_text, re.IGNORECASE)
                match = m_h or m_b
                if match:
                    v = parse_version(match.group(1))
                    if v:
                        signals["node_version"] = v
                        signals["version_source"] = f"{vpath} ({vc})"
                        signals["disclosure_path"] = vpath
                        break
            if signals["node_version"]:
                break
            # Presence signals from path bodies
            for pat in NODE_PRESENCE_PATTERNS:
                if re.search(pat, vb_text):
                    signals["body_node_presence"] = True
                    break

    return signals


# ---------------------------------------------------------------------------
# Triage logic — assign a bucket from signals
# ---------------------------------------------------------------------------

def triage(signals):
    """
    Returns (bucket, score, reason, detail) from collected signals.

    score is an integer:
      - For version-confirmed results: None (score doesn't apply)
      - For scored results: the raw signal score

    Bucket priority:
      CONFIRMED_VULNERABLE > CONFIRMED_PATCHED > LIKELY_NODE > POSSIBLE_NODE > UNLIKELY
    """
    if signals.get("error") and not signals.get("node_version"):
        if signals["http_status"] is None:
            return "ERROR", None, signals["error"], {}

    node_v = signals.get("node_version")

    # Version-based verdict (highest confidence, score = None — bypasses --min-score)
    if node_v:
        bucket, msg = version_verdict(node_v)
        return bucket, None, msg, {"version_tuple": node_v,
                                    "version_source": signals.get("version_source")}

    # No version — score signals for likelihood
    score = 0
    reasons = []

    if signals.get("express_header"):
        score += SIGNAL_SCORES["express_header"]
        reasons.append("X-Powered-By: Express")
    if signals.get("node_header"):
        score += SIGNAL_SCORES["node_header"]
        reasons.append("Node.js in Server/X-Powered-By header")
    if signals.get("brotli_response"):
        score += SIGNAL_SCORES["brotli_response"]
        reasons.append("Brotli response encoding (Content-Encoding: br)")
    if signals.get("connect_sid_cookie"):
        score += SIGNAL_SCORES["connect_sid_cookie"]
        reasons.append("connect.sid cookie (Express session middleware)")
    if signals.get("express_etag"):
        score += SIGNAL_SCORES["express_etag"]
        reasons.append("Weak ETag pattern (Express default)")
    if signals.get("body_node_presence"):
        score += SIGNAL_SCORES["body_node_presence"]
        reasons.append("Node.js/Express keywords in response body")
    if signals.get("interesting_paths"):
        score += SIGNAL_SCORES["interesting_paths"]
        reasons.append(f"Disclosure paths found: {', '.join(signals['interesting_paths'][:3])}")

    if score >= LIKELY_THRESHOLD:
        return "LIKELY_NODE", score, f"score={score}", {"signals": reasons}
    if score >= POSSIBLE_THRESHOLD:
        return "POSSIBLE_NODE", score, f"score={score}", {"signals": reasons}
    return "UNLIKELY", score, "no Node.js indicators", {}


# ---------------------------------------------------------------------------
# Per-target scan
# ---------------------------------------------------------------------------

def scan_target(raw_target, timeout=8):
    """Returns a result dict for a single target."""
    target = raw_target.strip()
    if not target or target.startswith("#"):
        return None

    # Normalize
    if not target.startswith("http"):
        target_url = "https://" + target
    else:
        target_url = target

    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = (parsed.scheme == "https")

    result = {
        "target":       raw_target.strip(),
        "host":         host,
        "port":         port,
        "tls":          use_tls,
        "bucket":       None,
        "score":        None,
        "reason":       None,
        "detail":       {},
        "signals":      {},
        "scanned_at":   datetime.now(timezone.utc).isoformat(),
    }

    try:
        signals = collect_signals(host, port, use_tls, timeout)

        # If HTTPS failed with connection error, retry HTTP
        if signals.get("error") in ("refused", "timeout") and use_tls:
            port_h = parsed.port or 80
            signals_h = collect_signals(host, port_h, False, timeout)
            if not signals_h.get("error"):
                signals = signals_h
                result["port"] = port_h
                result["tls"] = False

        result["signals"] = signals
        bucket, score, reason, detail = triage(signals)
        result["bucket"] = bucket
        result["score"] = score
        result["reason"] = reason
        result["detail"] = detail

    except Exception as e:
        result["bucket"] = "ERROR"
        result["score"] = None
        result["reason"] = str(e)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

BUCKET_ORDER = [
    "CONFIRMED_VULNERABLE", "CONFIRMED_PATCHED",
    "LIKELY_NODE", "POSSIBLE_NODE", "UNLIKELY", "ERROR"
]

def print_result(r, verbose=False):
    if not r:
        return
    bucket = r["bucket"]
    display = BUCKET_DISPLAY.get(bucket, bucket)
    lat = r["signals"].get("latency_ms")
    lat_str = f"  {DIM}{lat}ms{RESET}" if lat else ""
    score = r.get("score")
    score_str = f"  {DIM}score={score}{RESET}" if score is not None else ""
    print(f"  {display}  {r['target']}{lat_str}{score_str}")
    print(f"             {DIM}{r['reason']}{RESET}")

    if verbose:
        detail = r.get("detail", {})
        if "version_tuple" in detail:
            vt = detail["version_tuple"]
            vs = ".".join(str(x) for x in vt)
            print(f"             {DIM}version: v{vs}  source: {detail.get('version_source', '?')}{RESET}")
        if "signals" in detail:
            for s in detail["signals"]:
                print(f"             {DIM}signal: {s}{RESET}")
        sigs = r.get("signals", {})
        if sigs.get("interesting_paths"):
            for p in sigs["interesting_paths"][:5]:
                print(f"             {DIM}path: {p}{RESET}")
        if sigs.get("raw_headers_sample"):
            for k, v in list(sigs["raw_headers_sample"].items())[:4]:
                print(f"             {DIM}{k}: {v}{RESET}")


def write_json(results, path):
    clean = []
    for r in results:
        if not r:
            continue
        rc = dict(r)
        if "node_version" in rc.get("signals", {}):
            v = rc["signals"]["node_version"]
            if isinstance(v, tuple):
                rc["signals"]["node_version"] = list(v)
        if "version_tuple" in rc.get("detail", {}):
            v = rc["detail"]["version_tuple"]
            if isinstance(v, tuple):
                rc["detail"]["version_tuple"] = list(v)
        clean.append(rc)
    with open(path, "w") as f:
        json.dump(clean, f, indent=2, default=str)
    print(f"\n{tag('ok')} JSON written: {path}")


def write_csv(results, path):
    rows = []
    for r in results:
        if not r:
            continue
        sigs = r.get("signals", {})
        vt = sigs.get("node_version")
        rows.append({
            "target":             r["target"],
            "bucket":             r["bucket"],
            "score":              r.get("score", ""),
            "reason":             r["reason"],
            "node_version":       ".".join(str(x) for x in vt) if vt else "",
            "version_source":     sigs.get("version_source", ""),
            "brotli_response":    sigs.get("brotli_response", False),
            "express_header":     sigs.get("express_header", False),
            "latency_ms":         sigs.get("latency_ms", ""),
            "http_status":        sigs.get("http_status", ""),
            "interesting_paths":  " | ".join(sigs.get("interesting_paths", [])),
            "error":              sigs.get("error", ""),
            "scanned_at":         r.get("scanned_at", ""),
        })
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        w.writeheader()
        w.writerows(rows)
    print(f"{tag('ok')} CSV written: {path}")


def tag(level):
    return {"info": f"{C}[*]{RESET}", "ok": f"{G}[+]{RESET}",
            "warn": f"{Y}[!]{RESET}", "fail": f"{R}[-]{RESET}"}.get(level, "[?]")


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def passes_filters(result, min_score, bucket_filter):
    """
    Returns True if a result should be included in output / counts.

    Rules:
      - Version-confirmed buckets (CONFIRMED_VULNERABLE / CONFIRMED_PATCHED) always pass
        min_score (score is None for these, meaning the threshold doesn't apply).
      - Scored buckets (LIKELY_NODE / POSSIBLE_NODE / UNLIKELY) must have score >= min_score.
      - bucket_filter, if set, is the final gate: result.bucket must be in the set.
    """
    if not result:
        return False

    bucket = result.get("bucket")
    score = result.get("score")
    version_confirmed = bucket in ("CONFIRMED_VULNERABLE", "CONFIRMED_PATCHED")

    # min_score filter: skip non-version-confirmed results below threshold
    if min_score is not None and not version_confirmed:
        if score is None or score < min_score:
            return False

    # bucket filter
    if bucket_filter and bucket not in bucket_filter:
        return False

    return True


# ---------------------------------------------------------------------------
# Worker pool for bulk scanning
# ---------------------------------------------------------------------------

def worker(q, results, lock, timeout, verbose, min_score, bucket_filter):
    while True:
        item = q.get()
        if item is None:
            q.task_done()
            break
        try:
            r = scan_target(item, timeout=timeout)
            with lock:
                results.append(r)
                if passes_filters(r, min_score, bucket_filter):
                    print_result(r, verbose=verbose)
        finally:
            q.task_done()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-111497 (Node2Shell) passive triage scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output buckets:
  CONFIRMED VULNERABLE  — Node.js version found, below fixed threshold
  CONFIRMED PATCHED     — Node.js version found, at or above fixed threshold
  LIKELY NODE           — Strong Node.js/Express signals, version not disclosed  (score >= 40)
  POSSIBLE NODE         — Weaker signals (Brotli, ETag pattern, etc.)            (score >= 10)
  UNLIKELY              — No Node.js indicators detected                          (score < 10)

Scoring (scored path only — version-confirmed skips scoring):
  X-Powered-By: Express               +40
  Node.js in Server/X-Powered-By      +30
  connect.sid cookie                  +20
  Content-Encoding: br (Brotli)       +15
  Express-style weak ETag             +15
  Node.js keywords in body            +10
  Interesting disclosure paths        +5

Instrumentation switches:
  --min-score N           Only report scored results with score >= N.
                          Version-confirmed results always pass regardless of N.
  --buckets B[,B,...]     Only output results matching these bucket names.
                          Example: --buckets CONFIRMED_VULNERABLE,LIKELY_NODE

Recommended workflow:
  1. Run triage across all targets
  2. Deliver CONFIRMED VULNERABLE and LIKELY NODE buckets to customer
  3. Customer runs credentialed Nessus scan (or controlled test) on those hosts
  4. POSSIBLE NODE hosts: low priority, confirm with customer if they know the stack

Examples:
  python3 node2shell_triage.py https://target.example.com
  python3 node2shell_triage.py --input targets.txt --workers 10 --json results.json
  python3 node2shell_triage.py --input targets.txt --csv results.csv --verbose
  python3 node2shell_triage.py --input targets.txt --min-score 30
  python3 node2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_NODE
        """
    )
    parser.add_argument("target", nargs="?",
                        help="Single target URL or host:port")
    parser.add_argument("--input", "-i", metavar="FILE",
                        help="File with one target per line (URLs or host:port)")
    parser.add_argument("--workers", "-w", type=int, default=5,
                        help="Concurrent scan threads for bulk mode (default: 5)")
    parser.add_argument("--timeout", type=int, default=8,
                        help="Per-request timeout in seconds (default: 8)")
    parser.add_argument("--json", metavar="FILE",
                        help="Write full results to JSON file")
    parser.add_argument("--csv", metavar="FILE",
                        help="Write results to CSV file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show signal details per target")
    parser.add_argument("--min-score", type=int, default=None, metavar="N",
                        help="Only report scored results with score >= N. "
                             "Version-confirmed results always pass. (default: no filter)")
    parser.add_argument("--buckets", default=None, metavar="BUCKET[,BUCKET,...]",
                        help="Comma-separated list of bucket names to include in output. "
                             "Example: --buckets CONFIRMED_VULNERABLE,LIKELY_NODE")
    args = parser.parse_args()

    if not args.target and not args.input:
        parser.print_help()
        sys.exit(1)

    # Parse bucket filter
    bucket_filter = None
    if args.buckets:
        bucket_filter = set(b.strip().upper() for b in args.buckets.split(","))
        valid = set(BUCKET_ORDER)
        unknown = bucket_filter - valid
        if unknown:
            print(f"{tag('warn')} Unknown bucket name(s): {', '.join(unknown)}")
            print(f"         Valid buckets: {', '.join(BUCKET_ORDER)}")

    targets = []
    if args.target:
        targets.append(args.target)
    if args.input:
        with open(args.input) as f:
            targets.extend(ln.strip() for ln in f if ln.strip() and not ln.startswith("#"))

    print("=" * 68)
    print("  CVE-2026-111497 (Node2Shell) Passive Triage Scanner")
    print("=" * 68)
    print(f"  Targets  : {len(targets)}")
    print(f"  Workers  : {min(args.workers, len(targets))}")
    print(f"  Timeout  : {args.timeout}s per request")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Mode     : PASSIVE ONLY — no payloads, no behavioral probing")
    if args.min_score is not None:
        print(f"  Min score: {args.min_score} (version-confirmed always passes)")
    if bucket_filter:
        print(f"  Buckets  : {', '.join(sorted(bucket_filter))}")
    print("=" * 68 + "\n")

    results = []
    lock = threading.Lock()

    if len(targets) == 1:
        r = scan_target(targets[0], timeout=args.timeout)
        results.append(r)
        if passes_filters(r, args.min_score, bucket_filter):
            print_result(r, verbose=True)
    else:
        q = queue.Queue()
        threads = []
        n_workers = min(args.workers, len(targets))
        for _ in range(n_workers):
            t = threading.Thread(target=worker,
                                 args=(q, results, lock, args.timeout, args.verbose,
                                       args.min_score, bucket_filter),
                                 daemon=True)
            t.start()
            threads.append(t)
        for tgt in targets:
            q.put(tgt)
        for _ in range(n_workers):
            q.put(None)
        q.join()

    # Summary — counts over ALL results, display filtered
    results = [r for r in results if r]
    all_buckets = {}
    for r in results:
        b = r.get("bucket", "ERROR")
        all_buckets[b] = all_buckets.get(b, []) + [r["target"]]

    # Apply filters for output lists
    filtered = [r for r in results if passes_filters(r, args.min_score, bucket_filter)]
    filtered_buckets = {}
    for r in filtered:
        b = r.get("bucket", "ERROR")
        filtered_buckets[b] = filtered_buckets.get(b, []) + [r["target"]]

    print(f"\n{'=' * 68}")
    print(f"  {BOLD}SUMMARY{RESET}  ({len(results)} scanned, {len(filtered)} shown)")
    print(f"{'=' * 68}")
    for b in BUCKET_ORDER:
        all_count = len(all_buckets.get(b, []))
        shown_count = len(filtered_buckets.get(b, []))
        if not all_count:
            continue
        diff = f"  {DIM}({shown_count} shown){RESET}" if shown_count != all_count else ""
        print(f"  {BUCKET_DISPLAY.get(b, b)} : {all_count}{diff}")

    # Actionable list for customer handoff
    for_customer = (filtered_buckets.get("CONFIRMED_VULNERABLE", []) +
                    filtered_buckets.get("LIKELY_NODE", []))
    if for_customer:
        print(f"\n  {BOLD}Recommend for credentialed scan / customer testing:{RESET}")
        for t in for_customer:
            print(f"    {Y}→{RESET} {t}")

    possible = filtered_buckets.get("POSSIBLE_NODE", [])
    if possible:
        print(f"\n  {BOLD}Lower priority — confirm stack with customer:{RESET}")
        for t in possible[:10]:
            print(f"    {B}→{RESET} {t}")
        if len(possible) > 10:
            print(f"    {DIM}... and {len(possible) - 10} more{RESET}")

    print(f"\n  Fix : Node.js 22.23.4 / 24.22.1 / 26.12.1 | Brotli 1.0.10 / 1.1.1 / 1.2.1")
    print(f"  Ref : https://www.tenable.com/cve/CVE-2026-111497\n")

    if args.json:
        # JSON always gets all results regardless of filters
        write_json(results, args.json)
    if args.csv:
        # CSV likewise — filters are a display concern; let the analyst slice in Excel
        write_csv(results, args.csv)

    # Exit code for CI / pipeline use — based on all results, not filtered view
    if all_buckets.get("CONFIRMED_VULNERABLE"):
        sys.exit(2)   # definite hits
    if all_buckets.get("LIKELY_NODE"):
        sys.exit(1)   # candidates for follow-up
    sys.exit(0)


if __name__ == "__main__":
    main()
