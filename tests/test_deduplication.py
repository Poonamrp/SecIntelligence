import pytest
from src.database import get_db_session, init_db, Base, get_engine
from src.models import Advisory, Source
from src.services.normalize import NormalizedAdvisory
from src.services.change_detection import process_collected_advisories
from src.services.fingerprint import compute_content_hash

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_deduplication_same_advisory_twice():
    with get_db_session() as session:
        # Create test source
        src = session.query(Source).filter_by(name="Test Source").first()
        if not src:
            src = Source(name="Test Source", source_type="api", url="https://test.example.com", enabled=True)
            session.add(src)
            session.flush()

        adv1 = NormalizedAdvisory(
            stable_key="CVE-2024-1001",
            cve_id="CVE-2024-1001",
            source_name="Test Source",
            title="Sample Flaw in TestApp",
            canonical_url="https://test.example.com/1001",
            severity="High",
            cvss_score=8.5,
            description="Test vulnerability description"
        )

        # First collection
        new1, upd1, events1 = process_collected_advisories(session, src, [adv1], override_baseline=False)
        assert new1 == 1
        assert upd1 == 0
        assert len(events1) == 1

        # Second collection with identical data
        new2, upd2, events2 = process_collected_advisories(session, src, [adv1], override_baseline=False)
        assert new2 == 0
        assert upd2 == 0
        assert len(events2) == 0

        # Verify only one advisory exists in database
        count = session.query(Advisory).filter_by(stable_key="CVE-2024-1001").count()
        assert count == 1

def test_deterministic_hash_independent_of_fetch_timestamps():
    hash1 = compute_content_hash(
        title="Flaw in LibX",
        description="Stack overflow",
        severity="Critical",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_products=["LibX 1.0"],
        references=["https://example.com/ref1"],
        is_kev=False,
        zero_day_status="NONE"
    )

    hash2 = compute_content_hash(
        title="Flaw in LibX",
        description="Stack overflow",
        severity="Critical",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_products=["LibX 1.0"],
        references=["https://example.com/ref1"],
        is_kev=False,
        zero_day_status="NONE"
    )

    assert hash1 == hash2
