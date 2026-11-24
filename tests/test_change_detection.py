import json
import pytest
from src.database import get_db_session, init_db
from src.models import Advisory, Source, AdvisoryEvent
from src.services.normalize import NormalizedAdvisory
from src.services.change_detection import process_collected_advisories

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_change_detection_cvss_escalation():
    with get_db_session() as session:
        src = session.query(Source).filter_by(name="Change Test Source").first()
        if not src:
            src = Source(name="Change Test Source", source_type="api", url="https://change.example.com", enabled=True)
            session.add(src)
            session.flush()

        initial_adv = NormalizedAdvisory(
            stable_key="CVE-2024-2002",
            cve_id="CVE-2024-2002",
            source_name="Change Test Source",
            title="Initial Unscored Flaw",
            canonical_url="https://change.example.com/2002",
            severity="Medium",
            cvss_score=5.0,
            description="A flaw was discovered."
        )

        # Baseline insertion
        process_collected_advisories(session, src, [initial_adv], override_baseline=True)

        # Update: Score escalated to Critical 9.8
        updated_adv = NormalizedAdvisory(
            stable_key="CVE-2024-2002",
            cve_id="CVE-2024-2002",
            source_name="Change Test Source",
            title="Initial Unscored Flaw",
            canonical_url="https://change.example.com/2002",
            severity="Critical",
            cvss_score=9.8,
            description="A flaw was discovered. Remote Code Execution confirmed."
        )

        new_count, upd_count, events = process_collected_advisories(session, src, [updated_adv], override_baseline=False)
        assert new_count == 0
        assert upd_count == 1
        assert len(events) == 1
        assert events[0].event_type == "UPDATED"

        changes = json.loads(events[0].changes_json)
        assert "severity" in changes
        assert changes["severity"]["old"] == "Medium"
        assert changes["severity"]["new"] == "Critical"
        assert changes["cvss_score"]["new"] == 9.8

def test_change_detection_kev_addition():
    with get_db_session() as session:
        src = session.query(Source).filter_by(name="KEV Test Source").first()
        if not src:
            src = Source(name="KEV Test Source", source_type="api", url="https://kev.example.com", enabled=True)
            session.add(src)
            session.flush()

        # Initial advisory not in KEV
        adv = NormalizedAdvisory(
            stable_key="CVE-2024-3003",
            cve_id="CVE-2024-3003",
            source_name="KEV Test Source",
            title="Vulnerability before KEV",
            canonical_url="https://kev.example.com/3003",
            severity="High",
            cvss_score=8.0,
            is_kev=False
        )
        process_collected_advisories(session, src, [adv], override_baseline=True)

        # Later added to CISA KEV
        adv_kev = NormalizedAdvisory(
            stable_key="CVE-2024-3003",
            cve_id="CVE-2024-3003",
            source_name="KEV Test Source",
            title="Vulnerability now in KEV",
            canonical_url="https://kev.example.com/3003",
            severity="High",
            cvss_score=8.0,
            is_kev=True
        )
        new_count, upd_count, events = process_collected_advisories(session, src, [adv_kev], override_baseline=False)
        assert upd_count == 1
        assert len(events) == 1
        assert events[0].event_type == "KEV_ADDED"
