import responses
import pytest
from src.collectors.nvd import NvdCollector

MOCK_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-4004",
                "published": "2024-05-10T12:00:00.000",
                "lastModified": "2024-05-12T15:30:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "An unauthenticated remote code execution vulnerability in Acme Gateway."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ]
                },
                "references": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-4004"}
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"criteria": "cpe:2.3:a:acme:gateway:1.0:*:*:*:*:*:*:*"}
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    ]
}

@responses.activate
def test_nvd_collector_parsing():
    collector = NvdCollector(
        source_name="NVD Test",
        base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        config={"results_per_page": 10, "max_pages": 1}
    )

    responses.add(
        responses.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=MOCK_NVD_RESPONSE,
        status=200
    )

    advisories = collector.collect()
    assert len(advisories) == 1
    adv = advisories[0]

    assert adv.cve_id == "CVE-2024-4004"
    assert adv.stable_key == "CVE-2024-4004"
    assert adv.severity == "Critical"
    assert adv.cvss_score == 9.8
    assert adv.cvss_version == "3.1"
    assert "cpe:2.3:a:acme:gateway:1.0:*:*:*:*:*:*:*" in adv.affected_products
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-4004" in adv.references
