import datetime
from typing import List, Optional, Dict, Any
from src.collectors.base import BaseCollector
from src.services.normalize import NormalizedAdvisory, parse_iso_datetime
from src.services.classify import classify_severity, assess_zero_day

class GitHubAdvisoriesCollector(BaseCollector):
    """
    Collector for GitHub Global Security Advisories API.
    Endpoint: https://api.github.com/advisories
    """

    def __init__(
        self,
        source_name: str = "GitHub Advisories",
        base_url: str = "https://api.github.com/advisories",
        config: Optional[Dict[str, Any]] = None,
        github_token: Optional[str] = None
    ):
        super().__init__(source_name, base_url, config)
        self.github_token = github_token or self.config.get("github_token")
        self.per_page = int(self.config.get("per_page", 50))
        self.max_pages = int(self.config.get("max_pages", 3))

    def collect(self, last_check: Optional[datetime.datetime] = None) -> List[NormalizedAdvisory]:
        self.logger.info(f"Collecting GitHub Advisories (token present: {bool(self.github_token)})")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        params: Dict[str, Any] = {
            "per_page": self.per_page,
            "direction": "desc",
            "sort": "updated"
        }
        
        if last_check:
            # Buffer by 2 hours
            since_dt = last_check - datetime.timedelta(hours=2)
            params["modified_since"] = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        advisories: List[NormalizedAdvisory] = []
        page = 1

        while page <= self.max_pages:
            params["page"] = page
            self.logger.info(f"Fetching GitHub advisories page {page}")
            resp = self.http_client.get(self.base_url, params=params, headers=headers)
            items = resp.json()

            if not isinstance(items, list) or len(items) == 0:
                break

            for item in items:
                adv = self._parse_advisory(item)
                if adv:
                    advisories.append(adv)

            page += 1

        self.logger.info(f"Retrieved {len(advisories)} GitHub security advisories.")
        return advisories

    def _parse_advisory(self, item: Dict[str, Any]) -> Optional[NormalizedAdvisory]:
        ghsa_id = item.get("ghsa_id", "").strip().upper()
        cve_id = item.get("cve_id")
        if cve_id:
            cve_id = cve_id.strip().upper()

        if not ghsa_id and not cve_id:
            return None

        # Prefer CVE ID as stable key if present, otherwise GHSA ID
        stable_key = cve_id if cve_id else ghsa_id

        summary = item.get("summary", "")
        description = item.get("description", "")
        title = summary or f"{ghsa_id} Security Advisory"
        if cve_id and cve_id not in title:
            title = f"{cve_id} / {title}"

        pub_date = parse_iso_datetime(item.get("published_at"))
        mod_date = parse_iso_datetime(item.get("updated_at"))

        # Severity & CVSS
        cvss_data = item.get("cvss", {}) or {}
        cvss_score = cvss_data.get("score")
        cvss_vector = cvss_data.get("vector_string")
        raw_severity = item.get("severity")

        severity, parsed_score = classify_severity(cvss_score=cvss_score, explicit_label=raw_severity)

        # Affected packages
        affected_products = []
        for vuln in item.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            name = pkg.get("name")
            ecosystem = pkg.get("ecosystem")
            vulnerable_range = vuln.get("vulnerable_version_range")
            if name:
                entry = f"{ecosystem}:{name}" if ecosystem else name
                if vulnerable_range:
                    entry += f" ({vulnerable_range})"
                affected_products.append(entry)

        references = []
        for ref in item.get("references", []):
            if isinstance(ref, str):
                references.append(ref)
            elif isinstance(ref, dict) and "url" in ref:
                references.append(ref["url"])

        canonical_url = item.get("html_url") or f"https://github.com/advisories/{ghsa_id}"
        zero_day_status, zero_day_url = assess_zero_day(text=f"{summary}\n{description}")

        return NormalizedAdvisory(
            stable_key=stable_key,
            source_name=self.source_name,
            title=title,
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            canonical_url=canonical_url,
            summary=summary,
            description=description,
            published_at=pub_date,
            modified_at=mod_date,
            severity=severity,
            cvss_score=parsed_score,
            cvss_version="3.1" if cvss_vector and "CVSS:3.1" in cvss_vector else None,
            cvss_vector=cvss_vector,
            affected_products=affected_products[:20],
            references=references[:30],
            is_kev=False,
            zero_day_status=zero_day_status,
            zero_day_evidence_url=zero_day_url,
            raw_data={"ghsa_id": ghsa_id, "cve_id": cve_id}
        )
