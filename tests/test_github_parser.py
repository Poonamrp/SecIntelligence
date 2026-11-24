import responses
import pytest
from src.collectors.github_advisories import GitHubAdvisoriesCollector

MOCK_GITHUB_RESPONSE = [
    {
        "ghsa_id": "GHSA-1234-5678-90ab",
        "cve_id": "CVE-2024-7007",
        "summary": "Critical authentication bypass in auth-helper",
        "description": "auth-helper allows unauthenticated callers to bypass token validation.",
        "severity": "critical",
        "published_at": "2024-06-01T10:00:00Z",
        "updated_at": "2024-06-02T11:00:00Z",
        "cvss": {
            "score": 9.8,
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "vulnerabilities": [
            {
                "package": {
                    "name": "auth-helper",
                    "ecosystem": "npm"
                },
                "vulnerable_version_range": "< 2.0.0"
            }
        ],
        "references": [
            "https://github.com/advisories/GHSA-1234-5678-90ab"
        ],
        "html_url": "https://github.com/advisories/GHSA-1234-5678-90ab"
    }
]

@responses.activate
def test_github_advisories_collector():
    collector = GitHubAdvisoriesCollector(
        source_name="GitHub Test",
        base_url="https://api.github.com/advisories",
        config={"per_page": 10, "max_pages": 1}
    )

    responses.add(
        responses.GET,
        "https://api.github.com/advisories",
        json=MOCK_GITHUB_RESPONSE,
        status=200
    )

    advisories = collector.collect()
    assert len(advisories) == 1
    adv = advisories[0]

    assert adv.ghsa_id == "GHSA-1234-5678-90AB"
    assert adv.cve_id == "CVE-2024-7007"
    assert adv.stable_key == "CVE-2024-7007"
    assert adv.severity == "Critical"
    assert adv.cvss_score == 9.8
    assert "npm:auth-helper (< 2.0.0)" in adv.affected_products
