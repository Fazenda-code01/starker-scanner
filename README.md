# STARKER Security Scanner

![Version](https://img.shields.io/badge/version-5.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.9%2B-yellow)

Enterprise-grade **defensive security auditor**. Open source. Zero cost.

Designed to expose infrastructure vulnerabilities before attackers do.

---

## What it does

Runs 10 independent audit modules against any domain and returns a scored report:

| Module | What it checks |
|---|---|
| **SSL/TLS** | Certificate validity, expiry, cipher suite, protocol version |
| **HTTP Headers** | Presence of 11 mandatory security headers |
| **Cookies** | Secure, HttpOnly, SameSite flags |
| **DNS** | SPF, DMARC, DNSSEC, NS/MX records |
| **WHOIS** | Registrar, expiry date, organization |
| **Port Scan** | 33 common ports, 23 flagged as high-risk |
| **Subdomains** | 25 common subdomain patterns |
| **WAF Detection** | Cloudflare, Akamai, AWS WAF, Sucuri, F5, and more |
| **JS Libraries** | Fingerprints 12 common frameworks |
| **Redirect Chain** | HTTP → HTTPS enforcement |

**Scoring:** Sites start at 100. Each finding deducts weighted points.

| Score | Risk Level |
|---|---|
| 80–100 | LOW |
| 60–79 | MODERATE |
| 40–59 | HIGH |
| 0–39 | CRITICAL |

---

## Installation

### Via pip

```bash
pip install starker-scanner
starker-scan example.com
```

### Via Docker

```bash
docker run --rm starkerconsulting/scanner:5.0 example.com --format html > report.html
```

### From source

```bash
git clone https://github.com/YOUR_USERNAME/starker-scanner.git
cd starker-scanner
pip install -r requirements.txt
python scanner.py example.com
```

---

## Usage

```bash
# Basic scan (JSON output)
python scanner.py example.com

# HTML report
python scanner.py example.com --format html

# CSV export
python scanner.py example.com --format csv

# Custom output path
python scanner.py example.com --format html --output /reports/example

# Skip slow modules
python scanner.py example.com --skip-whois --skip-subdomains

# Verbose (shows all headers)
python scanner.py example.com --verbose

# Adjust performance
python scanner.py example.com --timeout 20 --workers 100
```

### All flags

| Flag | Default | Description |
|---|---|---|
| `--format` | `json` | Output format: `json`, `html`, `csv` |
| `--output` | auto | Output file path (no extension needed) |
| `--timeout` | `12` | Request timeout in seconds |
| `--workers` | `60` | Parallel threads for port scanning |
| `--skip-whois` | off | Skip WHOIS lookup |
| `--skip-ports` | off | Skip port scanning |
| `--skip-subdomains` | off | Skip subdomain enumeration |
| `--verbose` | off | Show all response headers |

---

## Output examples

### Terminal summary

```
============================================================
  [+] Executive Summary
============================================================
  Target            : example.com
  Score             : 74/100
  Risk              : MODERATE
  Penalties         : 6
  Open ports        : 3
  Subdomains found  : 4
  WAF/CDN           : Cloudflare
  Scan duration     : 14.32s
```

### HTML report

Full visual report with color-coded findings, organized tables for SSL, DNS, WHOIS, open ports, subdomains, and all HTTP headers.

### JSON report

Structured output for integration with SIEM, dashboards, or custom pipelines.

---

## Requirements

- Python 3.9+
- `requests`
- `python-whois`
- `dnspython` (optional — enhances DNS analysis)

---

## Legal

This tool is intended for **defensive security auditing only**.

Run it exclusively on:
- Domains you own
- Domains you have written authorization to test

Unauthorized scanning may violate local laws including the CFAA (US), Computer Misuse Act (UK), and equivalent legislation in your jurisdiction.

The authors accept no liability for misuse.

---

## License

MIT License — free for personal and commercial use.

---

## Built by

**STARKER Consulting** — Business intelligence and infrastructure security for physical and digital enterprises.
