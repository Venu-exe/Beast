![C](https://img.shields.io/badge/Language-C-00599C?style=for-the-badge&logo=c&logoColor=white) ![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black) ![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge) ![Version](https://img.shields.io/badge/Version-3.0-blue?style=for-the-badge) ![Bug Bounty Tool](https://img.shields.io/badge/Bug%20Bounty-Tool-red?style=for-the-badge&logo=hackthebox&logoColor=white)

# RECON

#### A fast, multi-threaded recon toolkit for bug bounty hunters — written in pure C.

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Modules](#modules) • [Examples](#real-world-examples) • [Workflow](#bug-bounty-workflow) • [License](#license)

---

```
 ____   _____ ____ ___  _   _
|  _ \ | ____/ ___/ _ \| \ | |
| |_) ||  _|| |  | | | |  \| |
|  _ < | |__| |__| |_| | |\  |
|_| \_\|_____\____\___/|_| \_|
  DNS + ports + subdomains + TLS + paths   v3.0
```

## Why recon?

Most recon tooling is a pile of Python/Go binaries glued together with shell scripts. **recon** is a single compiled C binary — multi-threaded, no runtime dependencies beyond `openssl` (already on every pentest box), and it covers the first hour of a bug bounty engagement in one command.

It combines **6 recon techniques** that map out a target's attack surface:

- 🌐 **DNS resolution** — A/AAAA records for a target
- 🔁 **Reverse DNS** — PTR lookup on the resolved IP
- 🧭 **Subdomain enumeration** — threaded wordlist brute force with CNAME + dangling-CNAME/takeover-candidate flagging
- 🔌 **Port scanning** — multi-threaded TCP connect scan with banner grabbing and HTTP fingerprinting
- 🔐 **TLS certificate inspection** — subject, issuer, SANs, and expiry warnings
- 🗂️ **HTTP path discovery** — checks common admin panels, secrets, and config files

## Features

| Feature | Description |
|---|---|
| **DNS + reverse DNS** | Resolves every A/AAAA record for a target and does a PTR lookup on the primary IP |
| **Threaded subdomain enum** | Wordlist-based brute force (built-in ~200-word list or your own) run across a worker-thread pool |
| **CNAME takeover flagging** | Flags subdomains whose CNAME points at a known third-party service (GitHub Pages, S3, Heroku, Azure, etc.) for manual dangling-CNAME review |
| **Multi-threaded port scan** | Non-blocking TCP connect scan over a curated top-port list, a range, or an explicit list |
| **Banner grabbing + HTTP fingerprinting** | Reads raw banners on open ports; on web ports, extracts the `Server:` header and `<title>` |
| **TLS certificate inspection** | Subject/issuer CN, validity window, SANs, and expiry warnings (expired / expiring soon) |
| **HTTP path discovery** | Checks ~50 common paths (`.git/config`, `.env`, `/admin`, `/actuator/health`, backups, etc.) with status codes |
| **Security header audit** | Grades A-F on HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP |
| **JSON output** | Machine-readable report for feeding into other tools/pipelines |
| **CSV output** | Flat, spreadsheet-friendly export of every subdomain/port/path finding |
| **Multi-target mode** | Run the whole pipeline over a list of targets from a file |
| **Rate limiting** | Configurable delay between brute-force requests to stay polite on shared infra |

## Installation

### Prerequisites

```bash
# Debian/Ubuntu/Kali
sudo apt install build-essential libssl-dev

# Fedora/RHEL
sudo dnf install gcc make openssl-devel

# Arch
sudo pacman -S openssl base-devel
```

### Build

```bash
git clone https://github.com/Venu-exe/Beast.git
cd Beast
make
```

That's it. Single binary at `bin/recon`, no pip, no npm, no cargo.

### Verify

```bash
./bin/recon --version
# recon v3.0
```

## Optional but recommanded

```
mkdir -p ~/.local/bin
cp ./bin/recon ~/.local/bin/<what name you want>

then execute that i have arch i use this

set -Ux fish_user_paths $fish_user_paths ~/.local/bin/<what name you want >

then exe

exec fish 

```

## Usage

```bash
./bin/recon <target> [options]
./bin/recon -L <targets_file> [options]
```

| Flag | Description | Default |
|---|---|---|
| `-p <ports>` | `"top"`, `"1-1000"`, or `"22,80,443"` | `top` |
| `-w <wordlist>` | subdomain wordlist path, or `default` for the built-in list | (disabled) |
| `-x <wordlist>` | enable HTTP path discovery; `default` or a wordlist file | (disabled) |
| `--tls` | probe TLS certificates on any TLS-looking open port | off |
| `--headers` | audit HTTP security headers and grade A-F | off |
| `-T <threads>` | worker threads for scan/brute-force modules | `50` (max `200`) |
| `-t <seconds>` | per-connection timeout | `2` |
| `-d <ms>` | delay between brute-force requests (politeness/rate limit) | `0` |
| `-o <file>` | write the text report to a file as well as stdout | (stdout only) |
| `-j <file>` | also write a machine-readable JSON report | (disabled) |
| `-c <file>` | also write a CSV report (subdomains/ports/paths, one row each) | (disabled) |
| `-L <file>` | run the full pipeline against every target in file (one per line) | (disabled) |
| `-s` | skip the port scan (DNS/subdomain/paths/TLS only) | off |
| `--no-color` | disable ANSI colors in terminal output | auto-detected |
| `-V`, `--version` | print version and exit | |
| `-h`, `--help` | show help | |

## Modules

### 🌐 DNS resolution + reverse DNS

Always runs first. Resolves every A/AAAA record for the target and performs a PTR lookup on the primary IPv4 address.

```bash
./bin/recon target.com -s
```

```
[*] DNS resolution for target.com:
      IPv4   93.184.216.34
      IPv6   2606:2800:220:1:248:1893:25c8:1946
[*] Reverse DNS: 93.184.216.34 -> (no PTR record)
```

---

### 🧭 Subdomain enumeration (threaded, CNAME-aware)

```bash
./bin/recon target.com -w wordlists/subdomains-small.txt -s
```

```
    [+] api.target.com -> 172.66.0.10  (CNAME: target.herokuapp.com -- review for possible dangling CNAME)
    [+] www.target.com -> 93.184.216.34
[*] Subdomain enumeration complete: 2 found (checked 216 candidates)
```

**Bug bounty use:** entries flagged with "review for possible dangling CNAME" point at a third-party service commonly abused for subdomain takeovers — worth a manual check with a tool like `subjack`/`tko-subs` or by hand.

---

### 🔌 Port scan + banner grab + HTTP fingerprint

```bash
./bin/recon target.com -p top -T 100
```

```
    80     OPEN   HTTP/1.1 301 Moved Permanently
    443    OPEN    | Server: nginx/1.18.0 | Title: Target Inc
    22     OPEN   SSH-2.0-OpenSSH_8.9p1
```

---

### 🔐 TLS certificate inspection

```bash
./bin/recon target.com -p 443 --tls -s
```

```
[*] TLS certificate for target.com:443
    Subject CN : target.com
    Issuer CN  : DigiCert Global CA
    Valid from : Jan 10 00:00:00 2026 GMT
    Valid to   : Feb 09 23:59:59 2027 GMT
    Status     : valid (194 days remaining)
    SANs       : target.com, www.target.com, api.target.com
```

**Bug bounty use:** SANs often reveal internal hostnames and related domains; expired or soon-to-expire certs are worth flagging.

---

### 🗂️ HTTP path discovery

```bash
./bin/recon target.com -p 80,443 -x default -s
```

```
    [200] target.com/robots.txt (312 bytes)
    [403] target.com/admin (protected)
    [200] target.com/.git/config (1204 bytes)
```

**Bug bounty use:** an exposed `.git/config`, `.env`, or backup file is an immediate finding on most programs.

---

### 🛡️ HTTP security header audit

```bash
./bin/recon target.com -p 80,443 --headers -s
```

```
[*] HTTP security header audit for target.com:443
    [x] Strict-Transport-Security
    [ ] Content-Security-Policy -- no CSP -- reduces defense-in-depth against XSS
    [x] X-Content-Type-Options
    [ ] X-Frame-Options -- no clickjacking protection (consider frame-ancestors)
    [ ] Referrer-Policy -- referrer policy not set -- may leak URLs cross-origin
    [ ] Permissions-Policy -- no Permissions-Policy -- browser features not scoped
    [ ] Cross-Origin-Opener-Policy -- no COOP -- reduced isolation from cross-origin windows
    [ ] Cross-Origin-Resource-Policy -- no CORP set
    Grade      : C  (55/100)
```

**Bug bounty use:** missing headers are commonly accepted as low/info-severity findings on programs that take them; pair with a real XSS/clickjacking PoC for anything above informational.

## Real-World Examples

### Full recon pipeline on one target

```bash
./bin/recon target.com \
    -w wordlists/subdomains-small.txt \
    -x default \
    --tls \
    -T 100 -d 50 \
    -o report.txt -j report.json
```

### Recon across an entire scope list

```bash
# targets.txt: one host/domain per line, already confirmed in-scope
./bin/recon -L targets.txt -w default -x default --tls -j scope-report.json
```

### Fast port sweep only

```bash
./bin/recon target.com -p 1-1000 -T 150 -s
```

Wait — `-s` skips the port scan; drop it for an actual sweep:

```bash
./bin/recon target.com -p 1-1000 -T 150
```

## Bug Bounty Workflow

```
┌───────────────┐     ┌───────────────────┐     ┌──────────────────┐
│  DNS + rDNS    │────▶│  Subdomain enum    │────▶│  Port scan        │
│  (resolve)     │     │  (+ CNAME flags)   │     │  (per host)       │
└───────────────┘     └───────────────────┘     └──────────────────┘
                                                          │
                                                   ┌──────▼──────────┐
                                                   │  TLS cert probe  │
                                                   │  (SANs, expiry)  │
                                                   └──────┬──────────┘
                                                          │
                                                   ┌──────▼──────────┐
                                                   │  Path discovery  │
                                                   │  (.git, .env...) │
                                                   └─────────────────┘
```

## Project Architecture

```
recon/
├── Makefile              # GNU Make build system
├── LICENSE               # MIT License
├── README.md
├── .gitignore
├── include/
│   ├── common.h           # shared config, PortResult struct, report()/color macros
│   ├── report.h            # logging (stdout + optional file, colorized)
│   ├── dns_utils.h          # DNS resolution + reverse DNS + canonical-name lookup
│   ├── net_utils.h           # timeout-based connect()/recv()
│   ├── http_probe.h           # HTTP Server/<title> probing
│   ├── portscan.h               # multi-threaded TCP connect scan
│   ├── subdomain.h                # threaded wordlist subdomain enum + CNAME flags
│   ├── http_paths.h                # threaded HTTP common-path discovery
│   ├── tls_probe.h                  # OpenSSL TLS certificate inspection
│   └── json_report.h                 # JSON report builder
└── src/                  # implementation, mirrors include/
    ├── main.c              # CLI parsing + pipeline orchestration
    ├── report.c, dns_utils.c, net_utils.c
    ├── http_probe.c, portscan.c, subdomain.c
    ├── http_paths.c, tls_probe.c, json_report.c
└── wordlists/
    └── subdomains-small.txt   # ~200-entry default subdomain list
```

## Contributing

Pull requests are welcome. For major changes, open an issue first.

**Ideas for future modules:**

- [ ] Wayback Machine URL enumeration
- [ ] Certificate transparency (crt.sh) subdomain discovery
- [ ] Favicon hash fingerprinting for Shodan dorking
- [x] HTTP security header audit + grading
- [ ] TLS/cipher vulnerability scanning
- [x] Output to CSV
- [ ] Output to Markdown

## Disclaimer

> **This tool is intended for authorized security testing only.** Use it only against targets you have explicit permission to test (your own infrastructure, or targets within a bug bounty program's scope). Unauthorized scanning is illegal. The author takes no responsibility for misuse.

## License

[MIT License](LICENSE) — use it, fork it, hack with it.

## Author

**Venu** ([@Venu-exe](https://github.com/Venu-exe))

---

**If this tool helped you find a bug, consider giving it a ⭐**
