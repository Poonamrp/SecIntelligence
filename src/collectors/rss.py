import hashlib
import datetime
import feedparser
from typing import List, Optional, Dict, Any
from src.collectors.base import BaseCollector
from src.services.normalize import NormalizedAdvisory, extract_cve_id, parse_iso_datetime
from src.services.classify import classify_severity, assess_zero_day

class RssFeedCollector(BaseCollector):
    """
    Generic RSS / Atom feed collector for vendor and CERT feeds.
    Parses feeds, extracts CVE IDs automatically from content, and classifies severity.
    """

    def __init__(
        self,
        source_name: str,
        base_url: str,
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(source_name, base_url, config)

    def collect(self, last_check: Optional[datetime.datetime] = None) -> List[NormalizedAdvisory]:
        self.logger.info(f"Parsing RSS/Atom feed from {self.base_url}")
        
        # Fetch content with SafeHttpClient to enforce timeouts, redirects, and size limits
        resp = self.http_client.get(self.base_url)
        feed = feedparser.parse(resp.content)

        if feed.bozo and not feed.entries:
            err = getattr(feed, "bozo_exception", "Unknown feed parse error")
            self.logger.error(f"Failed to parse feed {self.base_url}: {err}")
            raise ValueError(f"Invalid RSS/Atom feed: {err}")

        entries = feed.entries
        self.logger.info(f"Feed returned {len(entries)} entries for {self.source_name}")

        advisories: List[NormalizedAdvisory] = []
        for entry in entries:
            title = entry.get("title", "").strip()
            link = entry.get("link", "").strip()
            if not link and not title:
                continue

            summary = entry.get("summary", "") or entry.get("description", "")
            
            # Extract date
            pub_date = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                try:
                    pub_date = datetime.datetime(*entry.published_parsed[:6])
                except Exception:
                    pub_date = None
            elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
                try:
                    pub_date = datetime.datetime(*entry.updated_parsed[:6])
                except Exception:
                    pub_date = None
            else:
                pub_date = parse_iso_datetime(entry.get("published") or entry.get("updated"))

            # Check if entry is older than last_check
            if last_check and pub_date and pub_date < (last_check - datetime.timedelta(hours=2)):
                continue

            # Auto-extract CVE ID from title or summary
            combined_text = f"{title}\n{summary}"
            cve_id = extract_cve_id(combined_text)

            # Determine stable key
            if cve_id:
                stable_key = cve_id
            else:
                # Deterministic hash of source + canonical link/id
                entry_id = entry.get("id") or link or title
                key_raw = f"{self.source_name}:{entry_id}"
                stable_key = f"{self.source_name[:10].upper()}-{hashlib.sha256(key_raw.encode('utf-8')).hexdigest()[:16]}"

            # Classify severity based on text labels
            severity, score = classify_severity(explicit_label=combined_text)
            zero_day_status, zero_day_url = assess_zero_day(text=combined_text)

            adv = NormalizedAdvisory(
                stable_key=stable_key,
                source_name=self.source_name,
                title=title or f"{self.source_name} Advisory",
                cve_id=cve_id,
                canonical_url=link or self.base_url,
                summary=summary[:300] if summary else None,
                description=summary,
                published_at=pub_date,
                modified_at=pub_date,
                severity=severity,
                cvss_score=score,
                affected_products=[],
                references=[link] if link else [],
                is_kev=False,
                zero_day_status=zero_day_status,
                zero_day_evidence_url=zero_day_url,
                raw_data={"id": entry.get("id"), "link": link}
            )
            advisories.append(adv)

        self.logger.info(f"Processed {len(advisories)} advisories from feed {self.source_name}")
        return advisories
