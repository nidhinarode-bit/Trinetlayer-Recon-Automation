"""
Trinetlayer- Bugcrowd Bug Bounty Target Scraper
Scrapes all bug bounty programs from Bugcrowd and extracts their in-scope targets.
Uses parallel browser workers for speed.
Outputs results to CSV.
"""

import csv
import json
import time
import re
import sys
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    StaleElementReferenceException,
    WebDriverException,
)

BASE_URL = "https://bugcrowd.com"
LISTING_URL = (
    "https://bugcrowd.com/engagements"
    "?category=bug_bounty&page={page}&sort_by=promoted&sort_direction=desc"
)
OUTPUT_CSV = "bugcrowd_targets.csv"
OUTPUT_JSON = "bugcrowd_targets.json"

WORKERS = 5

BLACKLISTED_SLUGS = {
    "featured", "new", "recent", "promoted", "closed", "archived",
    "upcoming", "all", "search", "programs", "crowdstream",
}

print_lock = Lock()
csv_lock = Lock()
json_data = {}  
json_lock = Lock()

def log(msg):
    with print_lock:
        print(msg)

def create_driver(headless=True):
    opts = Options()
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-images")
    opts.add_experimental_option("prefs", {"profile.managed_default_content_settings.images": 2})
    opts.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
    if headless:
        opts.add_argument("--headless=new")
    driver = webdriver.Chrome(options=opts)
    driver.implicitly_wait(3)
    return driver

def wait_for_page_load(driver, timeout=15):
    WebDriverWait(driver, timeout).until(
        lambda d: d.execute_script("return document.readyState") == "complete"
    )

def is_valid_program_slug(slug):
    """Check if a slug looks like a real program, not a Bugcrowd UI page."""
    if not slug:
        return False
    if slug in BLACKLISTED_SLUGS:
        return False
    # Must not have query params or extra path segments
    if "?" in slug or "/" in slug:
        return False
    # Must be a reasonable slug (letters, numbers, hyphens)
    if not re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]{1,100}$", slug):
        return False
    return True
def switch_to_table_view(driver):
    try:
        table_btn = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable(
                (By.CSS_SELECTOR, "label[for='program-index-layout__table']")
            )
        )
        table_btn.click()
        time.sleep(1.5)
        log("[+] Switched to table view")
    except TimeoutException:
        log("[!] Could not find table toggle, continuing anyway")

def get_total_pages(driver):
    try:
        select_el = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "select[data-testid='bc-pagination__page-selector']")
            )
        )
        options = select_el.find_elements(By.TAG_NAME, "option")
        total = max(int(opt.text.strip()) for opt in options if opt.text.strip().isdigit())
        log(f"[+] Total pages detected: {total}")
        return total
    except (TimeoutException, ValueError):
        try:
            suffix = driver.find_element(
                By.CSS_SELECTOR, ".bc-pagination__select-suffix strong"
            )
            return int(suffix.text.strip())
        except Exception:
            log("[!] Could not detect total pages, defaulting to 1")
            return 1


def scrape_engagement_links(driver):
    """Scrape engagement links from the current listing page."""
    links = []
    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "a[href*='/engagements/']"))
        )
    except TimeoutException:
        log("[!] No engagement links found on this page")
        return links

    anchors = driver.find_elements(By.CSS_SELECTOR, "a[href*='/engagements/']")
    for a in anchors:
        try:
            href = a.get_attribute("href")
            name = a.text.strip()
        except StaleElementReferenceException:
            continue

        if not href or not name:
            continue

        match = re.search(r"/engagements/([^/?#]+)", href)
        if not match:
            continue

        slug = match.group(1)
        if not is_valid_program_slug(slug):
            continue

        full_url = f"{BASE_URL}/engagements/{slug}"
        if (full_url, name) not in links:
            links.append((full_url, name))

    return links

def collect_all_engagement_links():
    """Use one browser to iterate all pages and collect engagement links."""
    driver = create_driver(headless=True)
    all_links = []
    seen_urls = set()

    try:
        driver.get(LISTING_URL.format(page=1))
        wait_for_page_load(driver)
        time.sleep(2)

        switch_to_table_view(driver)
        time.sleep(1)

        total_pages = get_total_pages(driver)

        for page_num in range(1, total_pages + 1):
            log(f"[*] Listing page {page_num}/{total_pages}...")
            if page_num > 1:
                driver.get(LISTING_URL.format(page=page_num))
                wait_for_page_load(driver)
                time.sleep(1.5)

            page_links = scrape_engagement_links(driver)
            new_count = 0
            for url, name in page_links:
                if url not in seen_urls:
                    seen_urls.add(url)
                    all_links.append((url, name))
                    new_count += 1
            log(f"    +{new_count} programs (total: {len(all_links)})")
    finally:
        driver.quit()

    return all_links


def scrape_targets_worker(work_item):
    """
    Worker function: creates its own browser, scrapes targets for one program.
    Returns (program_name, list_of_target_dicts).
    """
    idx, total, url, program_name = work_item
    targets = []
    driver = None

    try:
        driver = create_driver(headless=True)
        log(f"  [{idx}/{total}] {program_name}")

        driver.get(url)
        wait_for_page_load(driver)
        time.sleep(1.5)

        rows = driver.execute_script("""
            var sections = document.querySelectorAll('[class*="scope"]');
            // Look for a container/heading that indicates "In Scope"
            var headings = document.querySelectorAll('h4, h3, h2, [class*="heading"], [class*="title"]');
            var outOfScopeY = Infinity;
            for (var i = 0; i < headings.length; i++) {
                var text = headings[i].textContent.trim().toLowerCase();
                if (text.indexOf('out of scope') !== -1 || text === 'out-of-scope') {
                    outOfScopeY = headings[i].getBoundingClientRect().top;
                    break;
                }
            }
            // Only return rows that appear before the "Out of Scope" heading
            var allRows = document.querySelectorAll('table tbody tr');
            var inScopeRows = [];
            for (var j = 0; j < allRows.length; j++) {
                if (allRows[j].getBoundingClientRect().top < outOfScopeY) {
                    inScopeRows.push(allRows[j]);
                }
            }
            return inScopeRows;
        """)

        if not rows:
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight / 2);")
            time.sleep(1.5)
            rows = driver.execute_script("""
                var headings = document.querySelectorAll('h4, h3, h2, [class*="heading"], [class*="title"]');
                var outOfScopeY = Infinity;
                for (var i = 0; i < headings.length; i++) {
                    var text = headings[i].textContent.trim().toLowerCase();
                    if (text.indexOf('out of scope') !== -1 || text === 'out-of-scope') {
                        outOfScopeY = headings[i].getBoundingClientRect().top;
                        break;
                    }
                }
                var allRows = document.querySelectorAll('table tbody tr');
                var inScopeRows = [];
                for (var j = 0; j < allRows.length; j++) {
                    if (allRows[j].getBoundingClientRect().top < outOfScopeY) {
                        inScopeRows.push(allRows[j]);
                    }
                }
                return inScopeRows;
            """)

        for row in rows:
            try:
                td = row.find_elements(By.CSS_SELECTOR, "td[data-label='Name / Location']")
                if not td:
                    td = row.find_elements(By.TAG_NAME, "td")
                if not td:
                    continue

                cell = td[0]
                target_text = ""
                target_url = ""
                target_type = "unknown"
                icon = cell.find_elements(By.CSS_SELECTOR, "span.bc-icon--target")
                if icon:
                    tooltip = icon[0].get_attribute("data-tooltip-content")
                    if tooltip:
                        target_type = tooltip
                    else:
                        classes = icon[0].get_attribute("class") or ""
                        for t in ["website", "ios", "android", "api", "hardware", "other"]:
                            if f"bc-icon--{t}" in classes:
                                target_type = t
                                break

                endpoint_el = cell.find_elements(
                    By.CSS_SELECTOR, "code.cc-rewards-link-table__endpoint"
                )
                if endpoint_el:
                    link = endpoint_el[0].find_elements(By.TAG_NAME, "a")
                    if link:
                        target_text = link[0].text.strip()
                        target_url = link[0].get_attribute("href") or ""
                    else:
                        target_text = endpoint_el[0].text.strip()

                hint_el = cell.find_elements(
                    By.CSS_SELECTOR, ".bc-hint.cc-rewards-link-table__target-uri code"
                )
                if hint_el:
                    hint_text = hint_el[0].text.strip()
                    if hint_text and not target_url:
                        target_url = hint_text

                display = target_url if target_url else target_text
                if not display:
                    continue

                targets.append({
                    "program": program_name,
                    "target": display,
                    "target_name": target_text if target_text != display else "",
                    "type": target_type,
                })

            except StaleElementReferenceException:
                continue
            except Exception:
                continue

        try:
            page_text = driver.execute_script("""
                var headings = document.querySelectorAll('h4, h3, h2, [class*="heading"], [class*="title"]');
                var inScopeStart = null;
                var outOfScopeStart = null;
                for (var i = 0; i < headings.length; i++) {
                    var text = headings[i].textContent.trim().toLowerCase();
                    if (text.indexOf('in scope') !== -1 && text.indexOf('out') === -1) {
                        inScopeStart = headings[i];
                    }
                    if (text.indexOf('out of scope') !== -1 || text === 'out-of-scope') {
                        outOfScopeStart = headings[i];
                        break;
                    }
                }
                if (inScopeStart && outOfScopeStart) {
                    // Get text between in-scope heading and out-of-scope heading
                    var range = document.createRange();
                    range.setStartBefore(inScopeStart);
                    range.setEndBefore(outOfScopeStart);
                    var fragment = range.cloneContents();
                    var div = document.createElement('div');
                    div.appendChild(fragment);
                    return div.textContent;
                } else if (outOfScopeStart) {
                    // Get all text before out-of-scope
                    var range = document.createRange();
                    range.setStartBefore(document.body.firstChild);
                    range.setEndBefore(outOfScopeStart);
                    var fragment = range.cloneContents();
                    var div = document.createElement('div');
                    div.appendChild(fragment);
                    return div.textContent;
                }
                return document.body.textContent;
            """) or ""
            wildcards = re.findall(r"\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", page_text)
            existing = {t["target"] for t in targets}
            for wc in set(wildcards):
                if wc not in existing:
                    targets.append({
                        "program": program_name,
                        "target": wc,
                        "target_name": "",
                        "type": "wildcard",
                    })
        except Exception:
            pass
        if targets:
            flush_csv_rows(targets)
            flush_json(program_name, targets)

        log(f"    -> {program_name}: {len(targets)} targets (saved)")

    except TimeoutException:
        log(f"    [!] Timeout: {program_name}")
    except WebDriverException as e:
        log(f"    [!] Error: {program_name}: {e}")
    except Exception as e:
        log(f"    [!] Unexpected: {program_name}: {e}")
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    return program_name, targets

def flush_csv_rows(rows):
    """Append rows to CSV immediately (thread-safe). Creates header if file is new."""
    with csv_lock:
        write_header = False
        try:
            with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
                write_header = f.read(1) == ""
        except FileNotFoundError:
            write_header = True

        with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(["Program", "Target (Raw)", "Domain / Wildcard", "Target Name", "Type"])
            for t in rows:
                domain = extract_domain_from_target(t["target"])
                writer.writerow([t["program"], t["target"], domain, t["target_name"], t["type"]])

def flush_json(program_name, targets):
    """Merge this program's targets into the JSON file on disk (thread-safe)."""
    with json_lock:
        json_data[program_name] = [
            {
                "target": t["target"],
                "domain": extract_domain_from_target(t["target"]),
                "target_name": t["target_name"],
                "type": t["type"],
            }
            for t in targets
        ]
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

def extract_domain_from_target(target):
    target = target.strip()
    if target.startswith("*."):
        return target
    url_match = re.match(r"https?://([^/:]+)", target)
    if url_match:
        return url_match.group(1)
    if re.match(r"^[a-zA-Z0-9*.-]+\.[a-zA-Z]{2,}$", target):
        return target
    return target

def main():
    print("=" * 60)
    print("  Bugcrowd Bug Bounty Target Scraper")
    print(f"  Workers: {WORKERS} parallel browsers")
    print("=" * 60)

    print("\n--- Phase 1: Collecting engagement links ---")
    engagement_links = collect_all_engagement_links()
    print(f"\n[+] Total programs found: {len(engagement_links)}")

    if not engagement_links:
        print("[!] No programs found. Bugcrowd may have changed their layout.")
        return

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(["Program", "Target (Raw)", "Domain / Wildcard", "Target Name", "Type"])

    print(f"\n--- Phase 2: Scraping targets ({WORKERS} workers, live-saving) ---")
    work_items = [
        (i, len(engagement_links), url, name)
        for i, (url, name) in enumerate(engagement_links, 1)
    ]

    total_targets = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(scrape_targets_worker, item): item for item in work_items}
        for future in as_completed(futures):
            try:
                program_name, targets = future.result()
                total_targets += len(targets)
            except Exception as e:
                item = futures[future]
                log(f"[!] Worker crashed for {item[3]}: {e}")

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Programs scraped: {len(engagement_links)}")
    print(f"  Total targets:    {total_targets}")
    print(f"  CSV:  {OUTPUT_CSV}")
    print(f"  JSON: {OUTPUT_JSON}")
    print("=" * 60)

if __name__ == "__main__":
    main()
