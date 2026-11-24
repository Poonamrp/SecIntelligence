import pytest
from src.services.classify import classify_severity, assess_zero_day

def test_classify_severity_boundaries():
    # Critical: >= 9.0
    sev, score = classify_severity(cvss_score=10.0)
    assert sev == "Critical" and score == 10.0
    
    sev, score = classify_severity(cvss_score=9.0)
    assert sev == "Critical" and score == 9.0

    # High: 7.0 - 8.9
    sev, score = classify_severity(cvss_score=8.9)
    assert sev == "High" and score == 8.9
    
    sev, score = classify_severity(cvss_score=7.0)
    assert sev == "High" and score == 7.0

    # Medium: 4.0 - 6.9
    sev, score = classify_severity(cvss_score=6.9)
    assert sev == "Medium" and score == 6.9
    
    sev, score = classify_severity(cvss_score=4.0)
    assert sev == "Medium" and score == 4.0

    # Low: > 0.0 and < 4.0
    sev, score = classify_severity(cvss_score=3.9)
    assert sev == "Low" and score == 3.9
    
    sev, score = classify_severity(cvss_score=0.1)
    assert sev == "Low" and score == 0.1

def test_classify_severity_fallbacks():
    # Explicit label fallback when score is missing
    assert classify_severity(explicit_label="CRITICAL")[0] == "Critical"
    assert classify_severity(explicit_label="Important")[0] == "High"
    assert classify_severity(explicit_label="Moderate")[0] == "Medium"
    assert classify_severity(explicit_label="Low")[0] == "Low"

    # Missing or invalid score
    assert classify_severity(cvss_score=None, explicit_label=None)[0] == "Unknown"
    assert classify_severity(cvss_score=-5.0, explicit_label=None)[0] == "Unknown"
    assert classify_severity(cvss_score="invalid", explicit_label=None)[0] == "Unknown"

def test_zero_day_assessment_never_confirms_from_keywords_alone():
    # Text with zero-day keywords but no authoritative verification
    status, url = assess_zero_day("A new 0-day vulnerability is reported under active exploitation.")
    assert status == "UNVERIFIED_SIGNAL"
    assert url is None

    # Text with in-the-wild mention without verification
    status, url = assess_zero_day("Flaw actively exploited in the wild before patch release.")
    assert status == "UNVERIFIED_SIGNAL"
    assert url is None

    # Normal text without 0-day mention
    status, url = assess_zero_day("Routine buffer overflow vulnerability patched in version 2.1.")
    assert status == "NONE"
    assert url is None

def test_confirmed_zero_day_requires_evidence():
    status, url = assess_zero_day(
        text="Authoritative vendor alert on zero-day",
        has_confirmed_evidence=True,
        evidence_url="https://vendor.com/security/advisory-001"
    )
    assert status == "CONFIRMED_ZERO_DAY"
    assert url == "https://vendor.com/security/advisory-001"
