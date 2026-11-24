import datetime
from typing import List, Optional, Dict, Any
from src.collectors.base import BaseCollector
from src.services.normalize import NormalizedAdvisory, parse_iso_datetime
from src.services.classify import classify_severity, assess_zero_day

class CisaKevCollector(BaseCollector):
    """
    Collector for CISA Known Exploited Vulnerabilities (KEV) Catalog.
    Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    """

    def __init__(
        self,
        source_name: str = "CISA KEV",
        base_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(source_name, base_url, config)

    def collect(self, last_check: Optional[datetime.datetime] = None) -> List[NormalizedAdvisory]:
        self.logger.info(f"Fetching CISA KEV catalog from {self.base_url}")
        resp = self.http_client.get(self.base_url)
        data = resp.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        self.logger.info(f"Retrieved {len(vulnerabilities)} entries from CISA KEV")

        advisories: List[NormalizedAdvisory] = []
        for item in vulnerabilities:
            cve_id = item.get("cveID", "").strip().upper()
            if not cve_id:
                continue

            date_added_str = item.get("dateAdded")
            kev_date = parse_iso_datetime(date_added_str)
            
            # Filter if last_check provided (with a 2-day buffer for safety)
            if last_check and kev_date and kev_date < (last_check - datetime.timedelta(days=2)):
                continue

            vendor = item.get("vendorProject", "").strip()
            product = item.get("product", "").strip()
            vuln_name = item.get("vulnerabilityName", "").strip()
            short_desc = item.get("shortDescription", "").strip()
            req_action = item.get("requiredAction", "").strip()
            due_date = item.get("dueDate", "").strip()
            notes = item.get("notes", "").strip()

            affected = []
            if vendor or product:
                affected.append(f"{vendor} {product}".strip())

            title = f"CISA KEV: {cve_id} - {vuln_name or product}"
            full_desc = short_desc
            if req_action:
                full_desc += f"\n\nRequired Action: {req_action} (Due: {due_date})"
            if notes:
                full_desc += f"\nNotes: {notes}"

            canonical_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"
            
            # KEV does not automatically mean zero-day.
            # Keyword mentions in notes/descriptions are classified as UNVERIFIED_SIGNAL, not confirmed.
            zero_day_status, zero_day_url = assess_zero_day(
                text=full_desc,
                has_confirmed_evidence=False,
                evidence_url=None
            )

            # CISA KEV entries are known exploited; default to High severity
            severity, cvss_score = classify_severity(explicit_label="High")

            adv = NormalizedAdvisory(
                stable_key=cve_id,
                source_name=self.source_name,
                title=title,
                cve_id=cve_id,
                canonical_url=canonical_url,
                summary=vuln_name or short_desc[:200],
                description=full_desc,
                published_at=kev_date,
                modified_at=kev_date,
                severity=severity,
                cvss_score=cvss_score,
                affected_products=affected,
                references=[canonical_url],
                is_kev=True,
                kev_date_added=kev_date,
                zero_day_status=zero_day_status,
                zero_day_evidence_url=zero_day_url,
                raw_data=item
            )
            advisories.append(adv)

        self.logger.info(f"Processed {len(advisories)} relevant CISA KEV advisories.")
        return advisories
