```
  __________  _____   ________________    _____  ____________
 /_  __/ __ \/  _/ | / / ____/_  __/ /   /   \ \/ / ____/ __ \
  / / / /_/ // //  |/ / __/   / / / /   / /| |\  / __/ / /_/ /
 / / / _, _// // /|  / /___  / / / /___/ ___ |/ / /___/ _, _/
/_/ /_/ |_/___/_/ |_/_____/ /_/ /_____/_/  |_/_/_____/_/ |_|
```

<div align="center">

# RECON AUTOMATION TOOL

### Automated Reconnaissance Pipeline for Cybersecurity Professionals & Bug Bounty Hunters

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Nuclei](https://img.shields.io/badge/Nuclei-v3.3.7-4A90D9?style=flat-square&logo=nuclei&logoColor=white)](https://github.com/projectdiscovery/nuclei)
[![httpx](https://img.shields.io/badge/httpx-v1.6.9-orange?style=flat-square)](https://github.com/projectdiscovery/httpx)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue?style=flat-square)](.)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)](.)
[![Trinetlayer](https://img.shields.io/badge/Trinetlayer-Internal%20Tool-1a1f28?style=flat-square)](.)

---

**`CRITICAL`** &nbsp; **`HIGH`** &nbsp; **`MEDIUM`** &nbsp; **`LOW`** &nbsp; **`INFO`**

---

### 🔍 Scan Pipeline

```
[ Subdomain Enum ] → [ Dedup ] → [ httpx Probe ] → [ Live Filter 200 ] → [ Nuclei Scan ] → [ Report ]
```

</div>

---

## 01 · Features

| Module | Description |
|---|---|
| **Enumeration** | Multi-tool subdomain discovery via subfinder, assetfinder, findomain, chaos, and crt.sh with automatic deduplication across all sources |
| **Vulnerability Scanning** | Nuclei with automatic template selection (`-as`), all severities, configurable rate limiting, dual TXT + JSONL output |
| **Live Host Probing** | httpx probing to identify live hosts. Full severity breakdown displayed after each scan completion |
| **Flexible Input** | CLI args, text files, JSON files, interactive mode. Bugcrowd target scraping integration included |
| **Structured Reporting** | Formatted scan summary reports. JSONL output for downstream SIEM or pipeline integration |
| **VPS / CI Ready** | Non-interactive mode, log file output, graceful signal handling. Cross-platform: Windows, macOS, Linux |

---

## 02 · Prerequisites

- ![Python](https://img.shields.io/badge/-Python%203.8+-3776AB?style=flat-square&logo=python&logoColor=white)
- ![Go](https://img.shields.io/badge/-Go%201.21+-00ADD8?style=flat-square&logo=go&logoColor=white)
- ![Required](https://img.shields.io/badge/-httpx%20%26%20nuclei%20%E2%80%94%20mandatory-9b72e8?style=flat-square)

Go 1.21+ is required for compiling and installing the core recon toolchain.  
Ensure `~/go/bin` is on your `$PATH` before proceeding.

---

## 03 · Installation

### Step 1 — Clone the Repository

```bash
git clone <repository-url>
cd "Recon automation"
```

### Step 2 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Install Recon Tools

> **httpx** and **nuclei** are mandatory. subfinder, assetfinder, findomain, and chaos are optional but significantly improve coverage.

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
# 1. Install Go from https://go.dev/dl/ (.msi installer)
# 2. Open a new terminal and run:

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

Install findomain: download the Windows binary from [github.com/Findomain/Findomain/releases](https://github.com/Findomain/Findomain/releases) and add it to PATH.

> ⚠️ **PATH Configuration — Windows**  
> If any tool shows `'command' is not recognized`, add `%USERPROFILE%\go\bin` to your system PATH.

```powershell
# Check Go bin path
go env GOPATH

# Add to PATH (run PowerShell as Administrator)
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";" + (go env GOPATH) + "\bin", "User")
```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
# Install Go
brew install go

# Install recon tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Install findomain
brew install findomain
```

Add Go bin to PATH — append to `~/.zshrc` or `~/.bash_profile`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
source ~/.zshrc
```

> ℹ️ **PATH Check:** Run `echo $PATH | tr ':' '\n' | grep go` — should show `/Users/<you>/go/bin`

</details>

<details>
<summary><b>🐧 Linux / VPS (Ubuntu / Debian)</b></summary>

```bash
# Install Go
sudo apt update && sudo apt install -y golang-go

# Or install latest Go manually:
# wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
# sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
# export PATH=$PATH:/usr/local/go/bin

# Install recon tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Install findomain
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip && chmod +x findomain
sudo mv findomain /usr/local/bin/
```

```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

> ℹ️ **PATH Check:** Run `echo $PATH | tr ':' '\n' | grep go` — should show `/home/<you>/go/bin`

</details>

### Verify All Tools

```bash
python3 -c "import requests; print('requests:', requests.__version__)"
go version
httpx -version
nuclei -version
subfinder -version
assetfinder -h
findomain --version
chaos -version
```

Expected output (version numbers may vary):

```
requests: 2.32.3
go version go1.22.0 linux/amd64
Current Version: v1.6.9
Nuclei engine version: v3.3.7
Current Version: v2.6.7
Usage of assetfinder: ...
Findomain version: 9.0.4
Current Version: v0.5.2
```

---

## 04 · Usage

### Interactive Mode — Windows / macOS

```bash
python recon.py
```

Launches a menu to scrape Bugcrowd, enter domains manually, or load from a file.

### CLI Mode — All Platforms

```bash
# Single domain
python recon.py -d example.com

# Multiple domains (comma-separated)
python recon.py -d example.com,target.org,test.io

# Load from text file (one per line)
python recon.py -dL domains.txt

# Load from JSON file
python recon.py --json-file targets.json

# Scrape Bugcrowd targets
python recon.py --bugcrowd

# Custom output directory
python recon.py -d example.com --output-dir /path/to/output
```

### VPS Usage

> Always use CLI arguments on a VPS (no interactive mode without TTY).  
> Use `--log-file` to persist output across SSH disconnects.

**Background with nohup:**
```bash
nohup python recon.py -d example.com --log-file recon.log &
```

**Inside tmux or screen:**
```bash
tmux new -s recon
python recon.py -dL targets.txt --log-file scan.log
# Ctrl+B, D to detach  |  tmux attach -t recon to reconnect
```

**Cron (scheduled scan):**
```bash
crontab -e

# Daily scan at 02:00
0 2 * * * cd /opt/recon-automation && python recon.py -dL targets.txt --log-file /var/log/recon.log
```

---

## 05 · CLI Reference

| Argument | Description |
|---|---|
| `-d`, `--domains` | Domain(s) comma-separated |
| `-dL`, `--domain-list` | File with domains (one per line) |
| `--json-file` | JSON file with targets/domains |
| `--bugcrowd` | Scrape targets from Bugcrowd |
| `--output-dir` | Custom output directory |
| `--log-file` | Tee all output to a log file |

---

## 06 · Output

Results saved to `results/<domain>_<timestamp>/`

| File | Description |
|---|---|
| `target_domains.txt` | Input domains |
| `all_subdomains.txt` | All discovered subdomains (deduplicated) |
| `httpx_output.txt` | Full httpx probe results with status codes |
| `live_subdomains.txt` | Live hosts responding with 200 OK |
| `nuclei_results.txt` | Nuclei vulnerability scan findings (text) |
| `nuclei_results.jsonl` | Nuclei findings in structured JSON (one object per line) |
| `recon_report.txt` | Formatted summary report |

---

## 07 · JSON Input Formats

The `--json-file` flag accepts multiple formats:

**Flat list:**
```json
["example.com", "target.org"]
```

**Object list:**
```json
[
  {"domain": "example.com"},
  {"domain": "target.org"}
]
```

**Bugcrowd-style (grouped by program):**
```json
{
  "program_name": [
    {"domain": "*.example.com"},
    {"domain": "target.org"}
  ]
}
```

---

## 08 · API Keys (Optional)

Configure API keys for subfinder to expand subdomain coverage via third-party intelligence sources.

```yaml
# ~/.config/subfinder/provider-config.yaml
shodan:
  - YOUR_SHODAN_API_KEY
securitytrails:
  - YOUR_SECURITYTRAILS_KEY
virustotal:
  - YOUR_VIRUSTOTAL_KEY
```

For chaos, export the environment variable:

```bash
export CHAOS_KEY=your-projectdiscovery-api-key
```

---

## 09 · Project Structure

```
Recon automation/
├── recon.py                 Main automation script
├── bugcrowd_scraper.py      Bugcrowd target scraper
├── requirements.txt         Python dependencies
├── results/                 Scan output directory
└── README.md                This file
```

---

## 10 · Troubleshooting

> ❌ **"MISSING REQUIRED TOOLS: httpx, nuclei"**  
> Go tools are not in your PATH. Run `echo $PATH` and ensure it includes `~/go/bin` or `$(go env GOPATH)/bin`.

---

> ⚠️ **httpx or nuclei not found after installation**  
> Close and reopen your terminal, or run `source ~/.bashrc` (Linux) / `source ~/.zshrc` (macOS).

---

> ℹ️ **crt.sh errors (502, timeout)**  
> The crt.sh API is occasionally slow or down. This is handled gracefully and does not affect other tools.

---

> ℹ️ **No live subdomains found**  
> httpx filters for 200 OK responses only. The target may return 301, 403, etc. Check `httpx_output.txt` for all responses.

---

> ❌ **Permission denied on VPS**  
> Ensure Go binaries have execute permissions: `chmod +x ~/go/bin/*`

---

<div align="center">

**Trinetlayer** &nbsp;·&nbsp; Internal Tool &nbsp;·&nbsp; Proprietary

Made by **Nidhi Appasaheb Narode** — AI Intern

</div>
