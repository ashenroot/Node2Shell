# Node2Shell — CVE-2026-111497 Detection Tooling

Authorized Engagement Use Only

Passive triage and behavioral detection tooling for CVE-2026-111497 — out-of-bounds write in the Brotli decoder bundled with Node.js.

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

> **Distro-packaged Node.js** (Debian, Alpine, RHEL, Amazon Linux) links against the system `libbrotli` (`--shared-brotli`). On those systems the Node.js package version is irrelevant — patch the system brotli library instead.

**Nessus coverage:** Plugin 370455 (FreeBSD local); Plugin 371226 (Rocky Linux TuxCare version check). Coverage is limited — use the triage script for broader detection.

---

## Tools

### `node2shell_triage.py` — Passive Triage Scanner

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
| `POSSIBLE_NODE` | Weaker signals — Brotli encoding, ETag pattern, etc. |
| `UNLIKELY` | No Node.js indicators |

**Scoring (scored path only — version-confirmed skips scoring):**

| Signal | Points |
|---|---|
| `X-Powered-By: Express` | +40 |
| `node` in Server/X-Powered-By | +30 |
| `connect.sid` cookie | +20 |
| Brotli response encoding | +15 |
| Express-style weak ETag | +15 |
| Node.js keywords in body | +10 |
| Interesting disclosure paths | +5 |

Thresholds: `LIKELY_NODE` ≥ 40 · `POSSIBLE_NODE` ≥ 10

**Exit codes:** `2` = confirmed vulnerable · `1` = likely candidates · `0` = clean (CI integration)

**Usage:**

```bash
# Single target
python3 node2shell_triage.py https://target.example.com

# Bulk from file
python3 node2shell_triage.py --input targets.txt --workers 10

# Output to JSON + CSV for reporting
python3 node2shell_triage.py --input targets.txt --json results.json --csv results.csv

# Verbose — show all signals per target
python3 node2shell_triage.py --input targets.txt --verbose

# Only show results scoring 30+ (version-confirmed always passes through)
python3 node2shell_triage.py --input targets.txt --min-score 30

# Only output confirmed vulnerable and likely candidates
python3 node2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_NODE
```

---

### `node2shell_probe.py` — Behavioral Probe

Three-stage behavioral detection against a single authorized target. **Can cause a crash** — requires explicit `--brotli-probe` flag and is intended for controlled testing on systems where the impact is understood.

**Stages:**

1. **Version fingerprinting** — passive header/body analysis (zero risk)
2. **Clustering detection** — determines if the target is behind a load balancer or reverse proxy where a crash would be absorbed
3. **Brotli payload probe** (gated behind `--brotli-probe`) — sends a malformed Brotli stream via pipelined HTTP/1.1; a canary request on the same TCP connection detects crash without a separate reconnect

**Usage:**

```bash
# Fingerprint + cluster detection only (safe)
python3 node2shell_probe.py https://target.example.com

# Full probe including behavioral test (authorized controlled testing only)
python3 node2shell_probe.py https://target.example.com --brotli-probe
```

---

## Instrumentation switches

### `--min-score N`

Filter console output (and `--buckets` application) to scored results with `score >= N`. Version-confirmed results (`CONFIRMED_VULNERABLE` / `CONFIRMED_PATCHED`) always pass regardless of `N` — they have no score and should never be suppressed.

JSON and CSV output always contains all results regardless of this flag, so you can slice the data in your own tooling.

```bash
# Tighten the feed — suppress POSSIBLE_NODE results scoring < 25
python3 node2shell_triage.py --input targets.txt --min-score 25
```

### `--buckets BUCKET[,BUCKET,...]`

Restrict console output to the named bucket(s). Valid names: `CONFIRMED_VULNERABLE`, `CONFIRMED_PATCHED`, `LIKELY_NODE`, `POSSIBLE_NODE`, `UNLIKELY`, `ERROR`.

```bash
# Hot targets only — skip everything below LIKELY_NODE
python3 node2shell_triage.py --input targets.txt --buckets CONFIRMED_VULNERABLE,LIKELY_NODE

# Combine with min-score for a tight feed
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

Python 3.8+, stdlib only — no external dependencies.

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
