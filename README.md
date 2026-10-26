# Node2Shell: CVE-2026-111497 Detection Tooling

Authorized Engagement Use Only

Passive triage and behavioral detection tooling for CVE-2026-111497 (out-of-bounds write in the Brotli decoder bundled with Node.js).

---

## Vulnerability Overview

| | |
|---|---|
| **CVE** | CVE-2026-111497 |
| **Component** | Google Brotli 1.0.3–1.2.0 (bundled in Node.js `deps/brotli`) |
| **Class** | Out-of-bounds write in `BrotliDecoderDecompressStream` (`c/dec/decode.c`) |
| **Trigger** | Brotli literal block-switch command when only one literal block type exists |
| **Attack surface** | Node.js `fetch()` (undici) decodes Brotli responses by default; Express 5 decompresses Brotli request bodies by default |
| **Impact** | Remote code execution / process crash |

### Fixed versions

| Release line | Fixed at |
|---|---|
| Node.js 22.x | 22.23.4 |
| Node.js 24.x | 24.22.1 |
| Node.js 26.x | 26.12.1 |
| Brotli (standalone) | 1.0.10 / 1.1.1 / 1.2.1 |

**EOL lines (18.x, 20.x) have no official fix.**

> **Distro-packaged Node.js** (Debian, Alpine, RHEL, Amazon Linux) links against the system `libbrotli` (`--shared-brotli`). On those systems the Node.js package version is irrelevant; patch the system brotli library instead.

**Nessus coverage:** Plugin 370455 (FreeBSD local); Plugin 371226 (Rocky Linux TuxCare version check). Coverage is limited; use the triage script for broader detection.

---

## Tools

### `node2shell_triage.py`: Passive Triage Scanner

Zero-risk passive sweep. No payloads. No behavioral probing. No crashes.

Collects observable signals from normal HTTP responses to bucket targets by likelihood of Node.js exposure, then hands confirmed and likely candidates to the customer for credentialed follow-up.

**Signals collected (all passive):**
- `X-Powered-By: Express` header
- `node` in `Server` or `X-Powered-By` header
- `connect.sid` session cookie (Express session middleware)
- `Content-Encoding: br` (Brotli responses active)
- Weak ETag in Express format (`W/"<hex>"`)
- Version strings in headers, response bodies, 404 error pages
- 20 common version/health disclosure paths (`/version`, `/health`, `/api/info`, etc.)

**Output buckets:**

| Bucket | Meaning |
|---|---|
| `CONFIRMED_VULNERABLE` | Version disclosed, below fix threshold |
| `CONFIRMED_PATCHED` | Version disclosed, at or above fix threshold |
| `LIKELY_NODE` | Strong Node.js/Express signals, version not disclosed |
| `POSSIBLE_NODE` | Weaker signals (Brotli encoding, ETag pattern, etc.) |
| `UNLIKELY` | No Node.js indicators |

**Scoring (scored path only; version-confirmed skips scoring):**

| Signal | Points |
|---|---|
| `X-Powered-By: Express` | +40 |
| `node` in Server/X-Powered-By | +30 |
| `connect.sid` cookie | +20 |
| Brotli response encoding | +15 |
| Express-style weak ETag | +15 |
| Node.js keywords in body | +10 |
| Interesting disclosure paths | +5 |

Thresholds: `LIKELY_NODE` >= 40 · `POSSIBLE_NODE` >= 10

**Exit codes:** `2` = confirmed vulnerable · `1` = likely candidates · `0` = clean (CI integration)

**Usage:**

```bash
# Single target
python3 node2shell_triage.py https://target.example.com

# Bulk from file
python3 node2shell_triage.py --input targets.txt --workers 10

# Output to JSON + CSV for reporting
python3 node2shell_triage.py --input targets.txt --json results.json --csv results.csv

# Verbose: show all signals per target
python3 node2shell_triage.py --input targets.txt --verbose

# Only show results scoring 30+ (version-confirmed always passes through)
python3 node2shell_triage.py --input targets.txt --min-score 30

# Only output confirmed vulnerable and likely candidates
python3 node2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_NODE
```

---

### `node2shell_probe.py`: Behavioral Probe

Three-stage behavioral detection against a single authorized target. **Can cause a crash.** Requires explicit `--brotli-probe` flag and is intended for controlled testing on systems where the impact is understood.

**Stages:**

1. **Version fingerprinting**: passive header/body analysis (zero risk)
2. **Clustering detection**: determines if the target is behind a load balancer or reverse proxy where a crash would be absorbed
3. **Brotli payload probe** (gated behind `--brotli-probe`): sends a malformed Brotli stream via pipelined HTTP/1.1; a canary request on the same TCP connection detects crash without a separate reconnect

**Usage:**

```bash
# Fingerprint + cluster detection only (safe)
python3 node2shell_probe.py https://target.example.com

# Full probe including behavioral test (authorized controlled testing only)
python3 node2shell_probe.py https://target.example.com --brotli-probe
```

---

## Understanding the scoring system

Signal weights reflect how much each indicator actually constrains the attack surface. High-weight signals are structurally difficult to fake or coincidentally produce, or directly indicate the specific exposure path for CVE-2026-111497.

### Why each signal is weighted the way it is

**`X-Powered-By: Express` (+40 — LIKELY threshold alone)**
Express sets this header by default and most production deployments leave it in place. Its presence is the strongest passive indicator that Node.js is serving the request. Express 5 enables Brotli body decompression by default, so this header directly implicates the attack surface. A target with only this header crosses into `LIKELY_NODE`; non-Node.js backends almost never emit `X-Powered-By: Express`.

**`node` in Server / X-Powered-By (+30)**
Catches backends that disclose `node` explicitly (e.g. `Server: Node.js/22.1.0`, `X-Powered-By: node`). Weighted slightly below Express because it's occasionally templated into reverse proxy headers or load balancer strings without Node.js actually serving the request, but still a high-confidence signal.

**`connect.sid` cookie (+20)**
The default session cookie name set by Express's `connect` session middleware. Applications that have renamed their session cookie won't emit this, so it's not definitive, but when present it's a strong corroborating signal that Express is handling sessions and the Brotli stack is likely in play.

**Brotli response encoding (+15)**
`Content-Encoding: br` means the Brotli codec path is exercised, which is the same code path CVE-2026-111497 lives in. Nginx, Caddy, and other proxies can also inject Brotli encoding, so this alone doesn't confirm Node.js. Combined with other signals, though, it's a meaningful indicator.

**Express-style weak ETag (+15)**
Express generates ETags in the format `W/"<hex-length>-<hex-hash>"` (e.g. `W/"6-lJr4pHWBM4"`). Distinctive enough to be a useful corroborating signal but weak in isolation.

**Node.js keywords in body (+10)**
Version strings, package names, or framework identifiers found in the response body, typically from a `/version`, `/health`, or similar endpoint. Lower weight because response bodies vary enormously; this can pick up documentation pages or error messages that mention Node.js tangentially.

**Interesting disclosure paths (+5)**
Non-404 responses to version/health endpoints like `/version`, `/health`, `/api/info`, `/metrics`. Useful to know these endpoints exist, but their content is captured by the body signal above. Weak additive signal only.

### How buckets work

The scoring path only runs when no version string is found. If a version is disclosed from any header, response body, or disclosure path, the result goes directly to `CONFIRMED_VULNERABLE` or `CONFIRMED_PATCHED`, bypassing scoring entirely.

For scored results:
- **LIKELY_NODE (>= 40):** At least one high-confidence structural indicator. The `Express` header alone gets you here. Prioritize for customer follow-up and credentialed scanning.
- **POSSIBLE_NODE (>= 10, < 40):** Weaker or more ambiguous signals. Worth logging but don't act on these without corroboration.
- **UNLIKELY (< 10):** No meaningful Node.js indicators. Keep in the output to account for all scanned targets.

### Worked examples

| Signals observed | Score | Bucket |
|---|---|---|
| Version disclosed: Node 22.1.0 | n/a | `CONFIRMED_VULNERABLE` (bypasses scoring) |
| Express header only | 40 | `LIKELY_NODE` |
| Express + connect.sid | 60 | `LIKELY_NODE` |
| Brotli encoding + ETag pattern | 30 | `POSSIBLE_NODE` |
| Node keyword in body only | 10 | `POSSIBLE_NODE` |
| No signals detected | 0 | `UNLIKELY` |

### Using `--min-score` effectively

The default (no filter) is the right starting point for most engagements. Use `--min-score` to tighten the feed for a specific workflow:

- `--min-score 40`: equivalent to "only LIKELY_NODE and above" in the scored tier (version-confirmed always passes)
- `--min-score 25`: cuts low-confidence POSSIBLE_NODE results (Brotli + ETag) while keeping those with a corroborating body signal
- `--min-score 10`: default behavior for scored results; all signals pass

Version-confirmed results always pass regardless of `--min-score`.

---

## Instrumentation switches

### `--min-score N`

Filter console output to scored results with `score >= N`. Version-confirmed results (`CONFIRMED_VULNERABLE` / `CONFIRMED_PATCHED`) always pass regardless of `N`; they have no score and are never filtered.

JSON and CSV output always contains all results regardless of this flag, so you can slice the data in your own tooling.

```bash
# Suppress POSSIBLE_NODE results scoring < 25
python3 node2shell_triage.py --input targets.txt --min-score 25
```

### `--buckets BUCKET[,BUCKET,...]`

Restrict console output to the named bucket(s). Valid names: `CONFIRMED_VULNERABLE`, `CONFIRMED_PATCHED`, `LIKELY_NODE`, `POSSIBLE_NODE`, `UNLIKELY`, `ERROR`.

```bash
# Skip everything below LIKELY_NODE
python3 node2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_NODE

# Combine with min-score
python3 node2shell_triage.py --input targets.txt --buckets LIKELY_NODE,POSSIBLE_NODE --min-score 20
```

The `--min-score` and `--buckets` flags control what is shown on the console. JSON / CSV always capture everything. Exit codes are based on all results.

---

## Recommended workflow

```
1. Run node2shell_triage.py across all customer-scoped targets
2. Deliver CONFIRMED_VULNERABLE and LIKELY_NODE lists to customer
3. Customer reviews list, confirms Node.js stack where unknown
4. For direct-access targets: run node2shell_probe.py --brotli-probe
   against confirmed authorized systems (coordinate with customer)
5. Document findings; reference CVE-2026-111497 in report
```

---

## Requirements

Python 3.8+, stdlib only. No external dependencies.

```bash
python3 node2shell_triage.py --help
python3 node2shell_probe.py --help
```

---

## References

- [CVE-2026-111497 — Tenable](https://www.tenable.com/cve/CVE-2026-111497)
- [Brotli upstream fix — commit 0ed4268](https://github.com/google/brotli/commit/0ed4268)
- [Node.js security advisories](https://nodejs.org/en/blog/vulnerability)

---

## License & Use

These tools are intended for use in authorized penetration testing engagements. Use only against systems you own or have explicit written authorization to test.
