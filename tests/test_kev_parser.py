import responses
import pytest
from src.collectors.cisa_kev import CisaKevCollector

MOCK_KEV_RESPONSE = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.05.15",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-5005",
            "vendorProject": "ExampleCorp",
            "product": "SecureRouter",
            "vulnerabilityName": "ExampleCorp SecureRouter Command Injection",
            "dateAdded": "2024-05-15",
            "shortDescription": "ExampleCorp SecureRouter contains an OS command injection flaw allowing remote code execution.",
            "requiredAction": "Apply vendor update or isolate device.",
            "dueDate": "2024-06-05",
            "notes": "Known active exploitation in the wild."
        }
    ]
}

@responses.activate
def test_cisa_kev_collector_parsing():
    collector = CisaKevCollector(
        source_name="CISA KEV Test",
        base_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    responses.add(
        responses.GET,
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        json=MOCK_KEV_RESPONSE,
        status=200
    )

    advisories = collector.collect()
    assert len(advisories) == 1
    adv = advisories[0]

    assert adv.cve_id == "CVE-2024-5005"
    assert adv.stable_key == "CVE-2024-5005"
    assert adv.is_kev is True
    assert adv.severity == "High"
    assert "ExampleCorp SecureRouter" in adv.affected_products
    assert adv.kev_date_added.strftime("%Y-%m-%d") == "2024-05-15"
    assert "Command Injection" in adv.title
