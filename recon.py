"""
TRINETLAYER --- Recon Automation Tool for Cybersecurity Professionals
- Option 1: Scrape targets from Bugcrowd, then run full recon
- Option 2: Input single or multiple domains manually
Pipeline: Subdomain Enum -> Dedup -> httpx -> Live filter (200) -> Nuclei -> Results
"""

import os
import sys
import subprocess
import shutil
import json
import re
import time
import signal
import argparse
import threading
import requests
from datetime import datetime

STARTUP_TIMEOUT = 120 
RESULTS_DIR = "results"
IS_INTERACTIVE = sys.stdin.isatty()

class TeeLogger:
    def __init__(self, log_path=None, terminal=None):
        self.terminal = terminal if terminal is not None else sys.stdout
        self.log_file = None
        if log_path:
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
            self.log_file = open(log_path, "a", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        if self.log_file:
            self.log_file.write(message)
            self.log_file.flush()

    def flush(self):
        self.terminal.flush()
        if self.log_file:
            self.log_file.flush()

    def isatty(self):
        return False

    def close(self):
        if self.log_file:
            self.log_file.close()
_running_procs = []

def _cleanup_handler(signum, frame):
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    print(f"\n[!] Received {sig_name}, cleaning up...")
    for proc in _running_procs:
        try:
            proc.kill()
        except Exception:
            pass
    sys.exit(1)

signal.signal(signal.SIGTERM, _cleanup_handler)
signal.signal(signal.SIGINT, _cleanup_handler)
if hasattr(signal, "SIGHUP"):
    signal.signal(signal.SIGHUP, _cleanup_handler)

def _safe_input(prompt, default=None):
    if IS_INTERACTIVE:
        return input(prompt)
    if default is not None:
        print(f"{prompt}[non-interactive, using default: {default}]")
        return default
    print(f"{prompt}[non-interactive, no default — skipping]")
    return ""

def banner():
    print(r"""
  __________  _____   ________________    _____  ____________
 /_  __/ __ \/  _/ | / / ____/_  __/ /   /   \ \/ / ____/ __ \
  / / / /_/ // //  |/ / __/   / / / /   / /| |\  / __/ / /_/ /
 / / / _, _// // /|  / /___  / / / /___/ ___ |/ / /___/ _, _/
/_/ /_/ |_/___/_/ |_/_____/ /_/ /_____/_/  |_/_/_____/_/ |_|
    """)

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def check_tool(name):
    """Check if a CLI tool is available on PATH."""
    return shutil.which(name) is not None

def check_dependencies():
    """Verify required tools are installed and warn about missing ones."""
    required = ["httpx", "nuclei"]
    optional = ["subfinder", "assetfinder", "findomain", "chaos"]

    missing_required = [t for t in required if not check_tool(t)]
    missing_optional = [t for t in optional if not check_tool(t)]

    if missing_required:
        print(f"\n[!] MISSING REQUIRED TOOLS: {', '.join(missing_required)}")
        print("    Install them before running this tool.")
        print("    httpx:   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("    nuclei:  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        sys.exit(1)

    if missing_optional:
        print(f"\n[*] Optional tools not found: {', '.join(missing_optional)}")
        print("    These will be skipped during subdomain enumeration.")
        print("    subfinder:   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("    assetfinder: go install -v github.com/tomnomnom/assetfinder@latest")
        print("    findomain:   https://github.com/Findomain/Findomain/releases")
        print("    chaos:       go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest")

    available = [t for t in optional if check_tool(t)]
    print(f"\n[+] Available enum tools: {', '.join(available) if available else 'None'} + crt.sh (API)")
    print(f"[+] Required tools OK: {', '.join(required)}")
    return available

def get_bugcrowd_domains():
    json_file = "bugcrowd_targets.json"

    if os.path.exists(json_file):
        print(f"\n[?] Found existing {json_file}.")
        choice = _safe_input("    Use existing data? (y/n): ", default="y").strip().lower()
        if choice == "y":
            return parse_bugcrowd_json(json_file)

    print("\n[*] Running Bugcrowd scraper... (this may take a while)")
    try:
        subprocess.run([sys.executable, "bugcrowd_scraper.py"], check=True)
    except subprocess.CalledProcessError:
        print("[!] Bugcrowd scraper failed.")
        return []
    except FileNotFoundError:
        print("[!] bugcrowd_scraper.py not found.")
        return []

    if os.path.exists(json_file):
        return parse_bugcrowd_json(json_file)
    return []

def parse_bugcrowd_json(json_file):
    domains = set()
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    for program, targets in data.items():
        for t in targets:
            domain = t.get("domain", "").strip().lower()
            if not domain:
                continue
        
            domain = re.sub(r'now$', '', domain)
            if domain.startswith("*."):
                domain = domain[2:]
            domain = domain.rstrip(".")
            if not domain:
                continue
            if re.match(r"^(com|io|org)\.[a-z]+\.[a-z]+$", domain):
                continue
            if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,12}$", domain):
                domains.add(domain)

    domain_list = sorted(domains)
    print(f"\n[+] Extracted {len(domain_list)} unique domains from Bugcrowd data")

    if domain_list:
        print("\n[*] Domains found:")
        for i, d in enumerate(domain_list[:20], 1):
            print(f"    {i}. {d}")
        if len(domain_list) > 20:
            print(f"    ... and {len(domain_list) - 20} more")

        print("\n[?] Options:")
        print("    1. Run recon on ALL domains")
        print("    2. Select specific domains by number (e.g., 1,3,5-10)")
        print("    3. Cancel")
        choice = _safe_input("\n    Choose [1/2/3]: ", default="1").strip()

        if choice == "1":
            return domain_list
        elif choice == "2":
            print("\n    All domains:")
            for i, d in enumerate(domain_list, 1):
                print(f"    {i}. {d}")
            selection = _safe_input("\n    Enter numbers (e.g., 1,3,5-10): ", default="").strip()
            selected = parse_selection(selection, len(domain_list))
            return [domain_list[i] for i in selected]
        else:
            return []
    return domain_list

def parse_selection(selection_str, max_val):
    indices = set()
    for part in selection_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for i in range(int(start), int(end) + 1):
                    if 1 <= i <= max_val:
                        indices.add(i - 1)
            except ValueError:
                pass
        else:
            try:
                i = int(part)
                if 1 <= i <= max_val:
                    indices.add(i - 1)
            except ValueError:
                pass
    return sorted(indices)

def parse_json_data(data):
    """Extract domains from parsed JSON data (dict or list format)."""
    domains = set()
    if isinstance(data, dict):
        for program, targets in data.items():
            if isinstance(targets, list):
                for t in targets:
                    if isinstance(t, dict):
                        raw = t.get("domain") or t.get("target") or t.get("host") or ""
                    elif isinstance(t, str):
                        raw = t
                    else:
                        continue
                    _add_domain(raw, domains)
            elif isinstance(targets, str):
                _add_domain(targets, domains)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                _add_domain(item, domains)
            elif isinstance(item, dict):
                raw = item.get("domain") or item.get("target") or item.get("host") or item.get("url") or ""
                _add_domain(raw, domains)
    return sorted(domains)

def load_json_file(filepath):
    """Load and parse a JSON file, return sorted domain list."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}")
        return []
    return parse_json_data(data)

def get_json_domains():
    filepath = _safe_input("\n    Enter JSON file path: ", default="").strip().strip('"')
    domain_list = load_json_file(filepath)
    if domain_list:
        print(f"\n[+] Extracted {len(domain_list)} unique domain(s) from JSON:")
        for d in domain_list[:20]:
            print(f"    - {d}")
        if len(domain_list) > 20:
            print(f"    ... and {len(domain_list) - 20} more")
    return domain_list

def _clean_domain(raw):
    """Clean and validate a raw domain/URL string. Returns cleaned domain or None."""
    d = raw.strip().lower()
    if d.startswith("*."):
        d = d[2:]
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    d = d.rstrip(".")
    if d and re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,12}$", d):
        if not re.match(r"^(com|io|org)\.[a-z]+\.[a-z]+$", d):
            return d
    return None

def _add_domain(raw, domain_set):
    d = _clean_domain(raw)
    if d:
        domain_set.add(d)

def parse_domains_from_text(text):
    """Parse domains from comma/newline separated text. Returns sorted list."""
    domains = set()
    for line in text.replace(",", "\n").split("\n"):
        d = _clean_domain(line)
        if d:
            domains.add(d)
    return sorted(domains)

def get_manual_domains():
    print("\n[?] Input method:")
    print("    1. Type domain(s) manually (comma or newline separated)")
    print("    2. Load from a text file (one domain per line)")
    choice = _safe_input("\n    Choose [1/2]: ", default="1").strip()

    if choice == "2":
        filepath = _safe_input("    Enter file path: ", default="").strip().strip('"')
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return []
        with open(filepath, "r") as f:
            raw = f.read()
    else:
        if not IS_INTERACTIVE:
            print("[!] Manual domain input requires an interactive terminal. Use -d or -dL instead.")
            return []
        print("    Enter domain(s) — comma or newline separated (type 'done' on empty line to finish):")
        lines = []
        while True:
            line = input("    > ").strip()
            if line.lower() == "done" or (not line and lines):
                break
            lines.append(line)
        raw = "\n".join(lines)

    domain_list = parse_domains_from_text(raw)
    print(f"\n[+] {len(domain_list)} valid domain(s) loaded:")
    for d in domain_list:
        print(f"    - {d}")

    return domain_list

def run_tool_with_timeout(cmd, startup_timeout=STARTUP_TIMEOUT):
    tool_name = cmd[0] if cmd else "unknown"
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _running_procs.append(proc)
    except FileNotFoundError:
        print(f"      [!] {tool_name} not found, skipping...")
        return []
    except Exception as e:
        print(f"      [!] {tool_name} error: {e}")
        return []

    start_time = time.time()
    output_lines = []
    started = threading.Event()

    def read_output():
        for line in proc.stdout:
            started.set()
            stripped = line.strip()
            if stripped:
                output_lines.append(stripped)

    def drain_stderr():
        """Consume stderr so the pipe buffer never blocks the subprocess."""
        try:
            for _ in proc.stderr:
                pass
        except Exception:
            pass

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    stderr_drainer = threading.Thread(target=drain_stderr, daemon=True)
    stderr_drainer.start()

    while True:
        if started.is_set():
            break
        if proc.poll() is not None:
            reader.join(timeout=5)
            break
        if time.time() > start_time + startup_timeout:
            print(f"      [!] {tool_name} produced no output in {startup_timeout}s, skipping...")
            proc.kill()
            proc.wait()
            if proc in _running_procs:
                _running_procs.remove(proc)
            return []
        time.sleep(0.2)
    reader.join()
    stderr_drainer.join()
    proc.wait()
    if proc in _running_procs:
        _running_procs.remove(proc)
    return output_lines

def enum_subfinder(domain):
    """Subdomain enumeration using subfinder."""
    return run_tool_with_timeout(["subfinder", "-d", domain, "-silent", "-all"])

def enum_assetfinder(domain):
    """Subdomain enumeration using assetfinder."""
    return run_tool_with_timeout(["assetfinder", "--subs-only", domain])

def enum_findomain(domain):
    """Subdomain enumeration using findomain."""
    return run_tool_with_timeout(["findomain", "-t", domain, "-q"])

def enum_chaos(domain):
    """Subdomain enumeration using chaos."""
    chaos_key = os.environ.get("CHAOS_KEY", "61a4286d-69b7-406c-b542-d3c9a7358027")
    return run_tool_with_timeout(["chaos", "-d", domain, "-silent", "-key", chaos_key])

def enum_crtsh(domain):
    """Subdomain enumeration using crt.sh (no tool needed, uses API)."""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=60)
        if resp.status_code != 200:
            print(f"      [!] crt.sh returned status {resp.status_code}")
            return []
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lower()
                if line and not line.startswith("*") and line.endswith(domain):
                    subdomains.add(line)
        return list(subdomains)
    except requests.Timeout:
        print("      [!] crt.sh timed out after 60s, skipping...")
        return []
    except Exception as e:
        print(f"      [!] crt.sh error: {e}")
        return []
ENUM_TOOLS = {
    "subfinder": enum_subfinder,
    "assetfinder": enum_assetfinder,
    "findomain": enum_findomain,
    "chaos": enum_chaos,
    "crt.sh": enum_crtsh,  
}

def enumerate_subdomains(domain, available_tools):
    """Run all available tools for a single domain, merge & dedup results."""
    print(f"\n  [*] Enumerating subdomains for: {domain}")
    all_subs = set()

    tools_to_run = {name: func for name, func in ENUM_TOOLS.items()
                    if name in available_tools or name == "crt.sh"}

    tea_break_shown = False
    for tool_name, func in tools_to_run.items():
        print(f"      Running {tool_name}...", end=" ", flush=True)
        results = func(domain)
        valid = [s.lower() for s in results
                 if (s.endswith(f".{domain}") or s == domain)
                 and not s.startswith("*")]
        all_subs.update(valid)
        print(f"found {len(valid)} subdomains")

        if not tea_break_shown and len(all_subs) > 1000:
            print("\n  [*] This process may take a few minutes—feel free to take a short tea or coffee break in the meantime.\n")
            tea_break_shown = True

    print(f"  [+] {domain}: {len(all_subs)} unique subdomains after dedup")
    return all_subs

def enumerate_all_domains(domains, available_tools):
    """Run subdomain enumeration for all target domains."""
    print("\n" + "=" * 60)
    print("  PHASE 1: SUBDOMAIN ENUMERATION")
    print("=" * 60)

    all_subdomains = set()
    for domain in domains:
        subs = enumerate_subdomains(domain, available_tools)
        all_subdomains.update(subs)

    print(f"\n[+] Total unique subdomains across all domains: {len(all_subdomains)}")
    return sorted(all_subdomains)

def run_httpx(subdomains, output_dir):
    """Run httpx on all subdomains, return live hosts with status codes."""
    print("\n" + "=" * 60)
    print("  PHASE 2: HTTPX PROBE")
    print("=" * 60)

    subs_file = os.path.join(output_dir, "all_subdomains.txt")
    httpx_output = os.path.join(output_dir, "httpx_output.txt")
    live_file = os.path.join(output_dir, "live_subdomains.txt")

    with open(subs_file, "w") as f:
        f.write("\n".join(subdomains))
    print(f"\n[*] Saved {len(subdomains)} subdomains to {subs_file}")

    print("[*] Running httpx probe...")
    try:
        proc = subprocess.Popen(
            ["httpx", "-l", subs_file, "-sc", "-silent", "-no-color"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        _running_procs.append(proc)
        stdout, _ = proc.communicate()
        if proc in _running_procs:
            _running_procs.remove(proc)
        httpx_lines = [l.strip() for l in stdout.splitlines() if l.strip()]
    except Exception as e:
        print(f"[!] httpx error: {e}")
        httpx_lines = []

    with open(httpx_output, "w") as f:
        f.write("\n".join(httpx_lines))
    print(f"[+] httpx results saved to {httpx_output}")

    live_urls = []
    for line in httpx_lines:
        if "[200]" in line:
            url = line.split("[")[0].strip()
            if url:
                live_urls.append(url)

    with open(live_file, "w") as f:
        f.write("\n".join(live_urls))

    print(f"[+] Live subdomains (200 OK): {len(live_urls)}")
    print(f"[+] Saved to {live_file}")

    return live_urls, live_file

def run_nuclei(live_file, output_dir):
    """Run nuclei scan on live subdomains."""
    print("\n" + "=" * 60)
    print("  PHASE 3: NUCLEI SCAN")
    print("=" * 60)

    nuclei_output = os.path.join(output_dir, "nuclei_results.txt")
    nuclei_json = os.path.join(output_dir, "nuclei_results.jsonl")

    if not os.path.exists(live_file):
        print("[!] No live subdomains file found, skipping nuclei.")
        return

    with open(live_file, "r") as f:
        if not f.read().strip():
            print("[!] No live subdomains to scan, skipping nuclei.")
            return

    print(f"[*] Running full nuclei scan on live targets...")
    print(f"    Text output : {nuclei_output}")
    print(f"    JSON output : {nuclei_json}")
    print(f"    Mode        : All templates, all severities")
    print(f"    This may take a while depending on the number of targets\n")

    try:
        proc = subprocess.Popen(
            [
                "nuclei",
                "-l", live_file,
                "-o", nuclei_output,
                "-je", nuclei_json,
                "-as",
                "-rl", "150",
                "-bs", "50",
                "-c", "25",
                "-retries", "2",
                "-timeout", "10",
                "-no-color",
                "-stats",
                "-si", "30",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _running_procs.append(proc)
        def _read_nuclei_stderr():
            try:
                for line in proc.stderr:
                    line = line.strip()
                    if line:
                        print(f"    [stats] {line}")
            except Exception:
                pass

        _nuclei_err_thread = threading.Thread(target=_read_nuclei_stderr, daemon=True)
        _nuclei_err_thread.start()

        for line in proc.stdout:
            line = line.strip()
            if line:
                print(f"    {line}")

        proc.wait()
        _nuclei_err_thread.join(timeout=5)
        if proc in _running_procs:
            _running_procs.remove(proc)

        if os.path.exists(nuclei_output):
            with open(nuclei_output, "r") as f:
                findings = [l for l in f.readlines() if l.strip()]

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for finding in findings:
                fl = finding.lower()
                for sev in severity_counts:
                    if f"[{sev}]" in fl:
                        severity_counts[sev] += 1
                        break

            print(f"\n[+] Nuclei scan complete: {len(findings)} findings")
            print(f"    Critical : {severity_counts['critical']}")
            print(f"    High     : {severity_counts['high']}")
            print(f"    Medium   : {severity_counts['medium']}")
            print(f"    Low      : {severity_counts['low']}")
            print(f"    Info     : {severity_counts['info']}")
            print(f"[+] Text results : {nuclei_output}")
            print(f"[+] JSON results : {nuclei_json}")
        else:
            print("\n[*] Nuclei scan complete: no findings")

    except FileNotFoundError:
        print("[!] nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    except Exception as e:
        print(f"[!] Nuclei error: {e}")

def generate_report(domains, subdomains, live_urls, output_dir):
    """Generate a summary report."""
    report_file = os.path.join(output_dir, "recon_report.txt")
    nuclei_file = os.path.join(output_dir, "nuclei_results.txt")

    nuclei_count = 0
    if os.path.exists(nuclei_file):
        with open(nuclei_file, "r", encoding="utf-8", errors="replace") as f:
            nuclei_count = len([l for l in f.readlines() if l.strip()])
    W = 68  
    def box_line(content, left="║", right="║"):
        return f"  {left} {content.ljust(W)}{right}\n"

    def box_top():
        return f"  ╔{'═' * (W + 1)}╗\n"

    def box_bottom():
        return f"  ╚{'═' * (W + 1)}╝\n"

    def sec_top():
        return f"  ┌{'─' * (W + 1)}┐\n"

    def sec_mid():
        return f"  ├{'─' * (W + 1)}┤\n"

    def sec_bottom():
        return f"  └{'─' * (W + 1)}┘\n"

    def sec_line(content):
        return f"  │ {content.ljust(W)}│\n"

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n")
        f.write(box_top())
        f.write(box_line(""))
        f.write(box_line("  __________  _____   ________________    _____  ____________"))
        f.write(box_line(" /_  __/ __ \\/  _/ | / / ____/_  __/ /   /   \\ \\/ / ____/ __ \\"))
        f.write(box_line("  / / / /_/ // //  |/ / __/   / / / /   / /| |\\  / __/ / /_/ /"))
        f.write(box_line(" / / / _, _// // /|  / /___  / / / /___/ ___ |/ / /___/ _, _/"))
        f.write(box_line("/_/ /_/ |_/___/_/ |_/_____/ /_/ /_____/_/  |_/_/_____/_/ |_|"))
        f.write(box_line(""))
        f.write(box_line("                  R E C O N   R E P O R T"))
        f.write(box_line(""))
        f.write(box_bottom())

        f.write("\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        f.write("\n")
        f.write(sec_top())
        f.write(sec_line(f"TARGET DOMAINS ({len(domains)})"))
        f.write(sec_mid())
        for d in domains:
            f.write(sec_line(f"  {d}"))
        f.write(sec_bottom())

        f.write("\n")
        f.write(sec_top())
        f.write(sec_line("SCAN SUMMARY"))
        f.write(sec_mid())
        f.write(sec_line(f"  Subdomains Found .... {str(len(subdomains)).rjust(6)}"))
        f.write(sec_line(f"  Live Hosts (200) .... {str(len(live_urls)).rjust(6)}"))
        f.write(sec_line(f"  Nuclei Findings ..... {str(nuclei_count).rjust(6)}"))
        f.write(sec_bottom())

        f.write("\n")
        f.write(sec_top())
        f.write(sec_line("OUTPUT FILES"))
        f.write(sec_mid())
        f.write(sec_line(f"  all_subdomains.txt    ({len(subdomains)} entries)"))
        f.write(sec_line(f"  httpx_output.txt      (full httpx results)"))
        f.write(sec_line(f"  live_subdomains.txt   ({len(live_urls)} live hosts)"))
        f.write(sec_line(f"  nuclei_results.txt    ({nuclei_count} findings)"))
        f.write(sec_bottom())

        f.write("\n")
        f.write("  ─── Powered by TrinetLayer Recon Automation ───\n")
        f.write("\n")

    print(f"\n[+] Report saved to {report_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Recon Automation - TrinetLayer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py --bugcrowd                          Scrape Bugcrowd then run recon
  python recon.py -d example.com                      Single domain
  python recon.py -d example.com,target.org           Multiple domains (comma separated)
  python recon.py -dL domains.txt                     Load domains from file
  python recon.py --json-file targets.json            Load domains from JSON file
  python recon.py                                     Interactive mode (menu)
        """,
    )
    parser.add_argument("--bugcrowd", action="store_true", help="Scrape targets from Bugcrowd")
    parser.add_argument("-d", "--domains", type=str, help="Domain(s) comma-separated")
    parser.add_argument("-dL", "--domain-list", type=str, help="File with domains (one per line)")
    parser.add_argument("--json-file", type=str, help="JSON file with targets/domains")
    parser.add_argument("--output-dir", type=str, help="Custom output directory (default: auto-generated under results/)")
    parser.add_argument("--log-file", type=str, help="Tee all output to this log file (useful for nohup/screen/tmux)")
    args = parser.parse_args()

    if args.log_file:
        _real_stdout = sys.stdout
        _real_stderr = sys.stderr
        sys.stdout = TeeLogger(args.log_file, terminal=_real_stdout)
        sys.stderr = TeeLogger(args.log_file, terminal=_real_stderr)

    banner()

    available_tools = check_dependencies()
    domains = None
    source = "manual"

    if args.bugcrowd:
        source = "bugcrowd"
        domains = get_bugcrowd_domains()
    elif args.domains:
        domains = parse_domains_from_text(args.domains)
        print(f"\n[+] {len(domains)} domain(s) from CLI:")
        for d in domains:
            print(f"    - {d}")
    elif args.domain_list:
        if not os.path.exists(args.domain_list):
            print(f"[!] File not found: {args.domain_list}")
            return
        with open(args.domain_list, "r") as f:
            raw = f.read()
        domains = parse_domains_from_text(raw)
        print(f"\n[+] {len(domains)} domain(s) from {args.domain_list}:")
        for d in domains:
            print(f"    - {d}")
    elif args.json_file:
        source = "json"
        domains = load_json_file(args.json_file)
        if not domains:
            return
        print(f"\n[+] {len(domains)} domain(s) from {args.json_file}:")
        for d in domains[:20]:
            print(f"    - {d}")
        if len(domains) > 20:
            print(f"    ... and {len(domains) - 20} more")
    else:
        
        if not IS_INTERACTIVE:
            print("[!] No domains specified and no TTY available.")
            print("    Use CLI args: -d example.com, -dL domains.txt, --json-file targets.json, or --bugcrowd")
            return
        print("\n[?] Choose target source:")
        print("    1. Scrape from Bugcrowd (uses bugcrowd_scraper.py)")
        print("    2. Input domain(s) manually")
        print("    3. Load targets from a JSON file")
        choice = input("\n    Choose [1/2/3]: ").strip()

        if choice == "1":
            source = "bugcrowd"
            domains = get_bugcrowd_domains()
        elif choice == "2":
            domains = get_manual_domains()
        elif choice == "3":
            source = "json"
            domains = get_json_domains()
        else:
            print("[!] Invalid choice.")
            return

    if not domains:
        print("[!] No domains to scan. Exiting.")
        return

    if args.output_dir:
        output_dir = args.output_dir
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if source == "bugcrowd":
            dir_label = f"bugcrowd_{len(domains)}_{timestamp}"
        elif source == "json":
            dir_label = f"json_{len(domains)}_{timestamp}"
        elif len(domains) == 1:
            dir_label = f"{domains[0]}_{timestamp}"
        else:
            dir_label = f"multi_{len(domains)}_{timestamp}"
        output_dir = os.path.join(RESULTS_DIR, dir_label)
    ensure_dir(output_dir)
    print(f"\n[+] Results will be saved to: {output_dir}")

    with open(os.path.join(output_dir, "target_domains.txt"), "w") as f:
        f.write("\n".join(domains))
    subdomains = enumerate_all_domains(domains, available_tools)

    if not subdomains:
        print("[!] No subdomains found. Exiting.")
        return
 
    live_urls, live_file = run_httpx(subdomains, output_dir)

    if not live_urls:
        print("[!] No live subdomains found. Skipping nuclei.")
    else:     
        run_nuclei(live_file, output_dir)

    generate_report(domains, subdomains, live_urls, output_dir)

    print("\n" + "=" * 60)
    print("  RECON COMPLETE")
    print(f"  Results: {output_dir}")
    print("=" * 60)

if __name__ == "__main__":
    main()