import pytest
from unittest.mock import patch
from src.database import get_db_session, init_db
from src.models import EmailOutbox, AdvisoryEvent, Advisory
from src.services.outbox import enqueue_advisory_alerts, process_outbox

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_email_outbox_deduplication():
    with get_db_session() as session:
        # Create advisory & event
        adv = Advisory(
            stable_key="CVE-2024-6006",
            title="Critical Flaw with Alerts",
            canonical_url="https://example.com/6006",
            severity="Critical",
            cvss_score=9.9,
            content_hash="hash6006"
        )
        session.add(adv)
        session.flush()

        event = AdvisoryEvent(
            advisory_id=adv.id,
            event_type="NEW",
            new_hash="hash6006"
        )
        session.add(event)
        session.flush()

        # Enqueue alerts twice with configured recipient
        with patch("src.services.outbox.get_config") as mock_cfg:
            mock_cfg.return_value.alert_to = "security-team@example.com"
            mock_cfg.return_value.smtp_username = "admin@example.com"
            mock_cfg.return_value.email_notification_policy = "ALL_IMMEDIATE"

            count1 = enqueue_advisory_alerts(session, [event])
            assert count1 == 1

            # Second enqueue should be skipped due to deduplication key
            count2 = enqueue_advisory_alerts(session, [event])
            assert count2 == 0

        # Verify only 1 record exists in outbox
        total = session.query(EmailOutbox).filter_by(event_id=event.id).count()
        assert total == 1

def test_email_outbox_retry_on_failure():
    with get_db_session() as session:
        outbox_item = EmailOutbox(
            recipient="test@example.com",
            subject="Test Failure Handling",
            body="Test body",
            status="PENDING",
            attempts=0,
            deduplication_key="test-retry-key-1"
        )
        session.add(outbox_item)
        session.flush()

        # Mock EmailService to simulate an SMTP connection error
        with patch("src.services.outbox.EmailService.send_raw_email", side_effect=ConnectionError("SMTP Server unreachable")):
            sent_count = process_outbox(session)
            assert sent_count == 0

            # Reload item
            session.refresh(outbox_item)
            # Must remain FAILED/PENDING, NEVER falsely marked SENT
            assert outbox_item.status == "FAILED"
            assert outbox_item.attempts == 1
            assert "SMTP Server unreachable" in outbox_item.last_error
            assert outbox_item.sent_at is None
