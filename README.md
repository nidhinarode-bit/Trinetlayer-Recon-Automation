```
  __________  _____   ________________    _____  ____________
 /_  __/ __ \/  _/ | / / ____/_  __/ /   /   \ \/ / ____/ __ \
  / / / /_/ // //  |/ / __/   / / / /   / /| |\  / __/ / /_/ /
 / / / _, _// // /|  / /___  / / / /___/ ___ |/ / /___/ _, _/
/_/ /_/ |_/___/_/ |_/_____/ /_/ /_____/_/  |_/_/_____/_/ |_|
```

# Recon Automation Tool

Automated reconnaissance pipeline for cybersecurity professionals and bug bounty hunters.

**Pipeline:** Subdomain Enumeration --> Dedup --> httpx Probe --> Live Filter (200 OK) --> Nuclei Scan (auto templates, all severities, JSON + TXT output) --> Report

---

## Features

- Multi-tool subdomain enumeration (subfinder, assetfinder, findomain, chaos, crt.sh)
- Automatic deduplication across all tools
- httpx probing to identify live hosts
- Nuclei vulnerability scanning with automatic template selection (`-as`), all severities, rate limiting, and dual output (TXT + JSONL)
- Severity breakdown (critical/high/medium/low/info) displayed after scan
- Bugcrowd target scraping integration
- Multiple input methods: CLI args, text files, JSON files, interactive mode
- Formatted report generation with scan summary
- VPS-friendly: non-interactive mode, log file output, graceful signal handling
- Cross-platform: Windows, macOS, Linux

---

## Prerequisites

- **Python 3.8+**
- **Go 1.21+** (for installing recon tools)

---

## Installation

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd "Recon automation"
```

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Install Recon Tools

The tool requires **httpx** and **nuclei** (mandatory), and supports **subfinder**, **assetfinder**, **findomain**, and **chaos**.

#### Windows

1. Install Go from https://go.dev/dl/ (download the `.msi` installer).
2. Open a new terminal after installation and run:

```powershell
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

3. Install findomain: download the Windows binary from https://github.com/Findomain/Findomain/releases and add it to your PATH.

4. Verify all tools are installed:

```powershell
python -c "import requests; print('requests:', requests.__version__)"
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
go version go1.22.0 windows/amd64
Current Version: v1.6.9
Nuclei engine version: v3.3.7
Current Version: v2.6.7
Usage of assetfinder: ...
Findomain version: 9.0.4
Current Version: v0.5.2
```

If any tool shows `'command' is not recognized`, ensure `%USERPROFILE%\go\bin` is added to your system PATH:

```powershell
# Check current Go bin path
go env GOPATH

# Add to PATH (run in PowerShell as Administrator)
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";" + (go env GOPATH) + "\bin", "User")
```

Close and reopen your terminal after updating PATH.

#### macOS

```bash
# Install Go (if not already installed)
brew install go

# Install recon tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Install findomain via Homebrew
brew install findomain
```

Make sure `~/go/bin` is in your PATH. Add this to your `~/.zshrc` or `~/.bash_profile`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Then reload:

```bash
source ~/.zshrc
```

Verify all tools are installed:

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
go version go1.22.0 darwin/arm64
Current Version: v1.6.9
Nuclei engine version: v3.3.7
Current Version: v2.6.7
Usage of assetfinder: ...
Findomain version: 9.0.4
Current Version: v0.5.2
```

If any tool shows `command not found`, verify your PATH:

```bash
echo $PATH | tr ':' '\n' | grep go
# Should show something like: /Users/<you>/go/bin
```

#### Linux / VPS (Ubuntu/Debian)

```bash
# Install Go
sudo apt update
sudo apt install -y golang-go

# Or install the latest Go manually:
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
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
```

Add Go bin to PATH permanently:

```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

Verify all tools are installed:

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

If any tool shows `command not found`, verify your PATH:

```bash
echo $PATH | tr ':' '\n' | grep go
# Should show: /home/<you>/go/bin

# If missing, re-run:
source ~/.bashrc
```

---

## Usage

### Interactive Mode (Windows / macOS)

```bash
python recon.py
```

This launches a menu where you can choose to scrape Bugcrowd, enter domains manually, or load from a file.

### CLI Mode (All Platforms)

**Single domain:**

```bash
python recon.py -d example.com
```

**Multiple domains (comma-separated):**

```bash
python recon.py -d example.com,target.org,test.io
```

**Load domains from a text file (one per line):**

```bash
python recon.py -dL domains.txt
```

**Load domains from a JSON file:**

```bash
python recon.py --json-file targets.json
```

**Scrape targets from Bugcrowd:**

```bash
python recon.py --bugcrowd
```

**Custom output directory:**

```bash
python recon.py -d example.com --output-dir /path/to/output
```

### VPS Usage

On a VPS, always use CLI arguments (no interactive mode without a TTY). Use `--log-file` to save output so it survives SSH disconnects.

**Run in background with nohup:**

```bash
nohup python recon.py -d example.com --log-file recon.log &
```

**Run inside tmux or screen:**

```bash
tmux new -s recon
python recon.py -dL targets.txt --log-file scan.log
# Ctrl+B, D to detach. Reconnect later with: tmux attach -t recon
```

**Run from cron (scheduled scan):**

```bash
# Edit crontab
crontab -e

# Add a daily scan at 2 AM
0 2 * * * cd /opt/recon-automation && python recon.py -dL targets.txt --log-file /var/log/recon.log
```

---

## CLI Reference

| Argument | Description |
|---|---|
| `-d`, `--domains` | Domain(s) comma-separated |
| `-dL`, `--domain-list` | File with domains (one per line) |
| `--json-file` | JSON file with targets/domains |
| `--bugcrowd` | Scrape targets from Bugcrowd |
| `--output-dir` | Custom output directory |
| `--log-file` | Tee all output to a log file |

---

## Output

Results are saved to `results/<domain>_<timestamp>/` with the following files:

| File | Description |
|---|---|
| `target_domains.txt` | Input domains |
| `all_subdomains.txt` | All discovered subdomains (deduplicated) |
| `httpx_output.txt` | Full httpx probe results with status codes |
| `live_subdomains.txt` | Only live hosts responding with 200 OK |
| `nuclei_results.txt` | Nuclei vulnerability scan findings (text) |
| `nuclei_results.jsonl` | Nuclei findings in structured JSON (one JSON object per line) |
| `recon_report.txt` | Formatted summary report |

---

## JSON Input Formats

The `--json-file` flag supports multiple formats:

**Flat list:**

```json
["example.com", "target.org"]
```

**Object list:**

```json
[{"domain": "example.com"}, {"domain": "target.org"}]
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

## API Keys (Optional)

For better subdomain results, configure API keys for subfinder:

```bash
# Create/edit subfinder provider config
nano ~/.config/subfinder/provider-config.yaml
```

Add your API keys:

```yaml
shodan:
  - YOUR_SHODAN_API_KEY
securitytrails:
  - YOUR_SECURITYTRAILS_KEY
virustotal:
  - YOUR_VIRUSTOTAL_KEY
```

For chaos, set the `CHAOS_KEY` environment variable:

```bash
export CHAOS_KEY=your-projectdiscovery-api-key
```

---

## Project Structure

```
Recon automation/
    recon.py                 Main automation script
    bugcrowd_scraper.py      Bugcrowd target scraper
    requirements.txt         Python dependencies
    results/                 Scan output directory
    README.md                This file
```

---

## Troubleshooting

**"MISSING REQUIRED TOOLS: httpx, nuclei"**
Go tools are not in your PATH. Run `echo $PATH` and ensure it includes `~/go/bin` or `$(go env GOPATH)/bin`.

**httpx or nuclei not found after installation**
Close and reopen your terminal, or run `source ~/.bashrc` (Linux) / `source ~/.zshrc` (macOS).

**crt.sh errors (502, timeout)**
The crt.sh API is occasionally slow or down. This is handled gracefully and does not affect other tools.

**No live subdomains found**
httpx filters for 200 OK responses only. The target may return other status codes (301, 403, etc.). Check `httpx_output.txt` for all responses.

**Permission denied on VPS**
Ensure the Go binaries have execute permissions: `chmod +x ~/go/bin/*`

---

## License

Internal tool - Trinetlayer.

Made by **Nidhi Appasaheb Narode** - Trinetlayer (AI Intern)