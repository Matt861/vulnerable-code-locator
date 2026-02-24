import re
import requests
from urllib.parse import quote_plus, urljoin

BASE = "https://security.snyk.io"

def find_snyk_vuln_report_urls(identifier: str, *, snyk_id_prefix: str | None = None, timeout_s: int = 30) -> list[str]:
    """
    Returns Snyk vulnerability report URLs (https://security.snyk.io/vuln/SNYK-...)
    that match an identifier (CVE-..., GHSA-..., etc.) by scraping the public search page.

    snyk_id_prefix examples:
      - "SNYK-JAVA-"   (only Maven/Java vulns)
      - "SNYK-JS-"     (npm)
      - "SNYK-PYTHON-" (PyPI)
      - "SNYK-RHEL"    (OS feeds)
    """
    search_url = f"{BASE}/vuln/?search={quote_plus(identifier)}"
    html = requests.get(search_url, timeout=timeout_s).text

    # Grab all links under /vuln/ and then filter to canonical SNYK IDs
    paths = re.findall(r'href="(/vuln/[^"#?]+)"', html)
    urls = []
    seen = set()

    for p in paths:
        u = urljoin(BASE, p)
        # Keep only actual vulnerability report pages
        # (exclude the search page itself and other non-SNYK routes)
        if "/vuln/SNYK-" not in u:
            continue
        if snyk_id_prefix and f"/vuln/{snyk_id_prefix}" not in u:
            continue
        if u not in seen:
            seen.add(u)
            urls.append(u)

    return urls


if __name__ == "__main__":
    # Example: CVE to Java-only Snyk pages
    for url in find_snyk_vuln_report_urls("CVE-2023-6378", snyk_id_prefix="SNYK-JAVA-"):
        print(url)