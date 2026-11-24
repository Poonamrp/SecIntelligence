import hashlib
import datetime
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import List, Optional, Dict, Any
from src.collectors.base import BaseCollector
from src.services.normalize import NormalizedAdvisory, extract_cve_id
from src.services.classify import classify_severity, assess_zero_day

class HtmlListingCollector(BaseCollector):
    """
    HTML listing parser for official public vulnerability bulletin pages (such as CERT-In).
    Only parses explicitly permitted, publicly accessible index pages without authentication.
    """

    def __init__(
        self,
        source_name: str,
        base_url: str,
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(source_name, base_url, config)
        self.link_selector = self.config.get("link_selector", "a")
        self.max_items = int(self.config.get("max_items", 25))

    def collect(self, last_check: Optional[datetime.datetime] = None) -> List[NormalizedAdvisory]:
        self.logger.info(f"Parsing HTML advisory listing from {self.base_url}")
        resp = self.http_client.get(self.base_url)
        soup = BeautifulSoup(resp.text, "html.parser")

        links = soup.select(self.link_selector)
        self.logger.info(f"Found {len(links)} link elements matching '{self.link_selector}'")

        advisories: List[NormalizedAdvisory] = []
        seen_urls = set()

        for link_elem in links:
            if len(advisories) >= self.max_items:
                break

            href = link_elem.get("href")
            text = link_elem.get_text(strip=True)
            if not href or not text or len(text) < 10:
                continue

            full_url = urljoin(self.base_url, href)
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            # Auto-extract CVE
            cve_id = extract_cve_id(text)
            if cve_id:
                stable_key = cve_id
            else:
                key_raw = f"{self.source_name}:{full_url}"
                stable_key = f"{self.source_name[:10].upper()}-{hashlib.sha256(key_raw.encode('utf-8')).hexdigest()[:16]}"

            severity, score = classify_severity(explicit_label=text)
            zero_day_status, zero_day_url = assess_zero_day(text=text)

            adv = NormalizedAdvisory(
                stable_key=stable_key,
                source_name=self.source_name,
                title=text,
                cve_id=cve_id,
                canonical_url=full_url,
                summary=text[:300],
                description=text,
                published_at=datetime.datetime.utcnow(),
                modified_at=datetime.datetime.utcnow(),
                severity=severity,
                cvss_score=score,
                affected_products=[],
                references=[full_url],
                is_kev=False,
                zero_day_status=zero_day_status,
                zero_day_evidence_url=zero_day_url,
                raw_data={"url": full_url, "text": text}
            )
            advisories.append(adv)

        self.logger.info(f"Extracted {len(advisories)} advisories from HTML page {self.source_name}")
        return advisories
