<div align="center">

```
  __________  _____   ________________    _____  ____________
 /_  __/ __ \/  _/ | / / ____/_  __/ /   /   \ \/ / ____/ __ \
  / / / /_/ // //  |/ / __/   / / / /   / /| |\  / __/ / /_/ /
 / / / _, _// // /|  / /___  / / / /___/ ___ |/ / /___/ _, _/
/_/ /_/ |_/___/_/ |_/_____/ /_/ /_____/_/  |_/_/_____/_/ |_|
```

# RECON AUTOMATION TOOL

### Automated Reconnaissance Pipeline for Cybersecurity Professionals & Bug Bounty Hunters

*Multi-stage enumeration to vulnerability reporting — single command execution.*

<br>

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-3b82f6?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-1a1f28?style=for-the-badge)

![Stars](https://img.shields.io/github/stars/nidhinarode-bit/Trinetlayer-Recon-Automation?style=flat-square&color=3b82f6)
![Repo size](https://img.shields.io/github/repo-size/nidhinarode-bit/Trinetlayer-Recon-Automation?style=flat-square&color=3b82f6)
![Last commit](https://img.shields.io/github/last-commit/nidhinarode-bit/Trinetlayer-Recon-Automation?style=flat-square&color=3b82f6)

`CRITICAL` &nbsp; `HIGH` &nbsp; `MEDIUM` &nbsp; `LOW` &nbsp; `INFO`

**[· View Live Page ·](https://nidhinarode-bit.github.io/Trinetlayer-Recon-Automation/)**

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture / Workflow](#architecture--workflow)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Screenshots / Demo](#screenshots--demo)
- [Configuration](#configuration)
- [Example Output](#example-output)
- [Security Disclaimer](#security-disclaimer)
- [Performance & Advantages](#performance--advantages)
- [Future Improvements](#future-improvements)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

Reconnaissance is the most time-consuming and repetitive phase of any security
assessment. An analyst typically runs five or six separate tools by hand, copies
output between them, removes duplicates manually, filters live hosts, and only
then begins vulnerability scanning. The process is slow, error-prone, and hard
to reproduce.

**Trinetlayer Recon Automation** wraps the entire recon phase in a single Python
orchestrator. One command takes a target from raw domain to a structured
vulnerability report, with every intermediate artifact saved to disk. It is built
for bug bounty hunters, penetration testers, and security teams who need fast,
consistent, and repeatable reconnaissance.

---

## Features

- 🔍 **Multi-source subdomain enumeration** — combines subfinder, assetfinder, findomain, chaos, and crt.sh, then deduplicates across every source.
- 🛡️ **Automated vulnerability scanning** — runs Nuclei with automatic template selection (`-as`) across all severity levels.
- 🌐 **Live host probing** — uses httpx to filter discovered subdomains down to hosts responding with `200 OK`.
- 📥 **Flexible input** — accepts CLI arguments, plain text files, JSON files, an interactive menu, or scraped Bugcrowd targets.
- 📊 **Structured reporting** — generates a human-readable summary plus JSONL output for SIEM or downstream pipeline integration.
- 🖥️ **VPS / CI ready** — non-interactive mode, log-file output, and graceful signal handling for unattended scans.
- 💻 **Cross-platform** — runs on Windows, macOS, and Linux.

---

## Architecture / Workflow

```
[ Subdomain Enum ] → [ Dedup ] → [ httpx Probe ] → [ Live Filter (200) ] → [ Nuclei Scan ] → [ Report ]
```

| Stage | What happens |
| ----- | ------------ |
| **1. Enumeration** | Runs all available subdomain tools against the target in sequence. |
| **2. Deduplication** | Merges results from every source into one clean, unique list. |
| **3. Probing** | httpx checks each subdomain for a live HTTP/HTTPS response. |
| **4. Live filtering** | Keeps only hosts returning `200 OK` for the scanning phase. |
| **5. Vulnerability scan** | Nuclei scans live hosts with auto-selected templates. |
| **6. Reporting** | Findings written as TXT + JSONL, plus a formatted summary report. |

---

## Tech Stack

| Category | Technologies |
| -------- | ------------ |
| **Language** | Python 3.8+ |
| **Recon toolchain** | subfinder, assetfinder, findomain, chaos, httpx, Nuclei |
| **Data sources** | crt.sh (certificate transparency), Bugcrowd |
| **Runtime dependency** | Go 1.21+ (required to install the recon toolchain) |
| **Python libraries** | See [`requirements.txt`](requirements.txt) |
| **Output formats** | TXT, JSONL |

---

## Installation

**Step 1 — Clone the repository**

```bash
git clone https://github.com/nidhinarode-bit/Trinetlayer-Recon-Automation.git
cd Trinetlayer-Recon-Automation
```

**Step 2 — Install Python dependencies**

```bash
pip install -r requirements.txt
```

**Step 3 — Install the recon toolchain (Go 1.21+ required)**

> `httpx` and `nuclei` are mandatory. subfinder, assetfinder, findomain, and chaos are optional but strongly improve coverage.

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

Install **findomain** separately (`brew install findomain` on macOS, or download the
release binary on Windows / Linux) and ensure `$(go env GOPATH)/bin` is on your `PATH`.

**Step 4 — Verify**

```bash
go version && httpx -version && nuclei -version
```

---

## Usage

**Interactive mode** (Windows / macOS):

```bash
python recon.py
```

**CLI mode** (all platforms):

```bash
# Single domain
python recon.py -d example.com

# Multiple domains
python recon.py -d example.com,target.org,test.io

# From a text file (one domain per line)
python recon.py -dL domains.txt

# From a JSON file
python recon.py --json-file targets.json

# Scrape targets from Bugcrowd
python recon.py --bugcrowd

# Custom output directory
python recon.py -d example.com --output-dir /path/to/output
```

### CLI Reference

| Argument | Description |
| -------- | ----------- |
| `-d`, `--domains` | Domain(s), comma-separated |
| `-dL`, `--domain-list` | File with domains (one per line) |
| `--json-file` | JSON file with targets/domains |
| `--bugcrowd` | Scrape targets from Bugcrowd |
| `--output-dir` | Custom output directory |
| `--log-file` | Tee all output to a log file |

---

## Project Structure

```
Trinetlayer-Recon-Automation/
├── recon.py              # Main automation orchestrator
├── bugcrowd_scraper.py   # Bugcrowd target scraper
├── requirements.txt      # Python dependencies
├── index.html            # Project landing page (GitHub Pages)
├── .gitignore
├── .gitattributes
└── README.md             # This file
```

---

## Screenshots / Demo

> 📸 **Screenshots coming soon.** A terminal capture of a live scan and a sample
> report will be added here. To contribute one, run a scan, save the image to an
> `assets/` folder, and reference it as `![Demo](assets/demo.png)`.
>
> A live project page is available at
> **[nidhinarode-bit.github.io/Trinetlayer-Recon-Automation](https://nidhinarode-bit.github.io/Trinetlayer-Recon-Automation/)**.

---

## Configuration

**API keys for subfinder** (optional — expands subdomain coverage):

```yaml
# ~/.config/subfinder/provider-config.yaml
shodan:
  - YOUR_SHODAN_API_KEY
securitytrails:
  - YOUR_SECURITYTRAILS_KEY
virustotal:
  - YOUR_VIRUSTOTAL_KEY
```

**API key for chaos:**

```bash
export CHAOS_KEY=your-projectdiscovery-api-key
```

Scan output paths are controlled by `--output-dir`; logging is controlled by `--log-file`.

---

## Example Output

Results are saved to `results/<domain>_<timestamp>/`:

| File | Description |
| ---- | ----------- |
| `target_domains.txt` | Input domains |
| `all_subdomains.txt` | All discovered subdomains (deduplicated) |
| `httpx_output.txt` | Full httpx probe results with status codes |
| `live_subdomains.txt` | Live hosts responding with `200 OK` |
| `nuclei_results.txt` | Nuclei findings (human-readable) |
| `nuclei_results.jsonl` | Nuclei findings (structured JSON) |
| `recon_report.txt` | Formatted summary report |

---

## Security Disclaimer

> ⚠️ **For authorized security testing only.**
>
> This tool performs active reconnaissance and vulnerability scanning. Use it
> **exclusively** against systems you own or for which you hold explicit, written
> permission to test. Unauthorized scanning is illegal in most jurisdictions and
> may carry criminal penalties. The author accepts **no liability** for misuse or
> for any damage resulting from use of this software.

---

## Performance & Advantages

- **One command instead of six** — replaces a manual multi-tool workflow with a single repeatable run.
- **No manual deduplication** — cross-source merging is automatic.
- **Reproducible** — every scan is timestamped and self-contained.
- **Pipeline-friendly** — JSONL output drops straight into SIEM or CI workflows.
- **Unattended operation** — non-interactive mode and log files support long VPS scans over SSH.

---

## Future Improvements

- [ ] Port scanning stage (e.g. naabu) before HTTP probing
- [ ] HTML / PDF report export in addition to TXT and JSONL
- [ ] Resume capability for interrupted scans
- [ ] Notification integrations (Slack / Discord / email) on scan completion
- [ ] Dockerfile for one-command containerized deployment
- [ ] Unit tests and CI pipeline

---

## Contributing

Contributions are welcome:

1. Fork the repository and create a feature branch.
2. Keep changes focused on lawful, defensive, and educational use.
3. Open a pull request with a clear description of the change.

Bug reports and feature requests can be filed via [Issues](https://github.com/nidhinarode-bit/Trinetlayer-Recon-Automation/issues).

---

</div>
