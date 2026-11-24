import time
import datetime
from typing import List, Optional, Dict, Any
from src.collectors.base import BaseCollector
from src.services.normalize import NormalizedAdvisory, parse_iso_datetime
from src.services.classify import classify_severity, assess_zero_day

class NvdCollector(BaseCollector):
    """
    Collector for NIST National Vulnerability Database (NVD) CVE API 2.0.
    Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
    """

    def __init__(
        self,
        source_name: str = "NVD",
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        config: Optional[Dict[str, Any]] = None,
        api_key: Optional[str] = None
    ):
        super().__init__(source_name, base_url, config)
        self.api_key = api_key or self.config.get("api_key")
        # Rate limit delays: with key 0.6s, without key 6.0s (NVD limit is 5 req / 30s without key)
        self.request_delay = 0.6 if self.api_key else 6.0
        self.max_results_per_page = int(self.config.get("results_per_page", 200))
        self.max_pages = int(self.config.get("max_pages", 5))

    def collect(self, last_check: Optional[datetime.datetime] = None) -> List[NormalizedAdvisory]:
        self.logger.info(f"Collecting from NVD API 2.0 (API key present: {bool(self.api_key)})")
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params: Dict[str, Any] = {
            "resultsPerPage": self.max_results_per_page,
            "startIndex": 0
        }

        # Date filtering with 2-hour overlap window to ensure no missed updates
        now_utc = datetime.datetime.utcnow()
        if last_check:
            start_dt = last_check - datetime.timedelta(hours=2)
            # NVD API expects ISO 8601 e.g. 2024-01-01T00:00:00.000
            params["lastModStartDate"] = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = now_utc.strftime("%Y-%m-%dT%H:%M:%S.000")
        else:
            # First run: limit to last 7 days of modifications to avoid massive initial payload
            start_dt = now_utc - datetime.timedelta(days=7)
            params["lastModStartDate"] = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = now_utc.strftime("%Y-%m-%dT%H:%M:%S.000")

        advisories: List[NormalizedAdvisory] = []
        page = 0

        while page < self.max_pages:
            self.logger.info(f"Fetching NVD page {page + 1} (startIndex={params['startIndex']})")
            resp = self.http_client.get(self.base_url, params=params, headers=headers)
            data = resp.json()

            cve_items = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)
            self.logger.info(f"NVD returned {len(cve_items)} items (total available: {total_results})")

            for item in cve_items:
                cve_obj = item.get("cve", {})
                adv = self._parse_nvd_cve(cve_obj)
                if adv:
                    advisories.append(adv)

            params["startIndex"] += len(cve_items)
            page += 1

            if params["startIndex"] >= total_results or len(cve_items) == 0:
                break

            time.sleep(self.request_delay)

        self.logger.info(f"Successfully collected {len(advisories)} advisories from NVD.")
        return advisories

    def _parse_nvd_cve(self, cve: Dict[str, Any]) -> Optional[NormalizedAdvisory]:
        cve_id = cve.get("id", "").strip().upper()
        if not cve_id:
            return None

        # Description in English
        desc_list = cve.get("descriptions", [])
        desc_en = ""
        for d in desc_list:
            if d.get("lang") == "en":
                desc_en = d.get("value", "")
                break
        if not desc_en and desc_list:
            desc_en = desc_list[0].get("value", "")

        pub_date = parse_iso_datetime(cve.get("published"))
        mod_date = parse_iso_datetime(cve.get("lastModified"))

        # Extract CVSS metrics (prefer v3.1, then v3.0, v4.0, then v2.0)
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_version = None
        cvss_vector = None
        explicit_sev = None

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            data_m = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = data_m.get("baseScore")
            cvss_version = data_m.get("version", "3.1")
            cvss_vector = data_m.get("vectorString")
            explicit_sev = data_m.get("baseSeverity")
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            data_m = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = data_m.get("baseScore")
            cvss_version = data_m.get("version", "3.0")
            cvss_vector = data_m.get("vectorString")
            explicit_sev = data_m.get("baseSeverity")
        elif "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
            data_m = metrics["cvssMetricV40"][0].get("cvssData", {})
            cvss_score = data_m.get("baseScore")
            cvss_version = data_m.get("version", "4.0")
            cvss_vector = data_m.get("vectorString")
            explicit_sev = data_m.get("baseSeverity")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            data_m = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = data_m.get("baseScore")
            cvss_version = data_m.get("version", "2.0")
            cvss_vector = data_m.get("vectorString")
            explicit_sev = metrics["cvssMetricV2"][0].get("baseSeverity")

        severity, parsed_score = classify_severity(cvss_score=cvss_score, explicit_label=explicit_sev)

        # References
        references = []
        for ref in cve.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        # Configurations / Affected products (CPEs)
        affected = []
        for config_node in cve.get("configurations", []):
            for node in config_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria")
                    if cpe:
                        affected.append(cpe)

        canonical_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        zero_day_status, zero_day_url = assess_zero_day(text=desc_en)

        title = f"{cve_id}: {desc_en[:120].strip()}..." if len(desc_en) > 120 else f"{cve_id}: {desc_en}"

        return NormalizedAdvisory(
            stable_key=cve_id,
            source_name=self.source_name,
            title=title,
            cve_id=cve_id,
            canonical_url=canonical_url,
            summary=desc_en[:300] if desc_en else None,
            description=desc_en,
            published_at=pub_date,
            modified_at=mod_date,
            severity=severity,
            cvss_score=parsed_score,
            cvss_version=str(cvss_version) if cvss_version else None,
            cvss_vector=cvss_vector,
            affected_products=affected[:20],  # Bounded to 20 for database storage efficiency
            references=references[:30],
            is_kev=False,  # Will be cross-referenced with KEV catalog
            zero_day_status=zero_day_status,
            zero_day_evidence_url=zero_day_url,
            raw_data={"id": cve_id}
        )
