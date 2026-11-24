import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from src.models import EmailOutbox, AdvisoryEvent, Advisory
from src.services.email_service import EmailService
from src.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger("outbox")

def should_notify_event(event: AdvisoryEvent, advisory: Advisory, policy: str) -> bool:
    """
    Evaluates whether an advisory event triggers an immediate email according to configured policy.
    
    Policies:
      - IMMEDIATE_CRITICAL_KEV: Critical, CISA KEV, or Confirmed 0-day
      - ALL_IMMEDIATE: Every new advisory or update
      - DISABLED: No automated alert emails
    """
    if policy == "DISABLED":
        return False
        
    if policy == "ALL_IMMEDIATE":
        return True

    # Default: IMMEDIATE_CRITICAL_KEV
    if advisory.is_kev:
        return True
    if advisory.zero_day_status == "CONFIRMED_ZERO_DAY":
        return True
    if advisory.severity == "Critical":
        return True
    if event.event_type in ("KEV_ADDED", "ZERO_DAY_CONFIRMED"):
        return True

    return False

def enqueue_advisory_alerts(session: Session, events: List[AdvisoryEvent]) -> int:
    """
    Enqueues outbound notification emails for newly generated events.
    Applies deduplication key constraint (event_id + recipient) to prevent duplicates.
    """
    cfg = get_config()
    recipient = cfg.alert_to or cfg.smtp_username
    if not recipient:
        logger.debug("No alert recipient configured (ALERT_TO); skipping outbox enqueue.")
        return 0

    enqueued = 0
    policy = cfg.email_notification_policy

    for event in events:
        advisory = session.query(Advisory).filter_by(id=event.advisory_id).first()
        if not advisory:
            continue

        if not should_notify_event(event, advisory, policy):
            continue

        dedup_key = f"event:{event.id}:{recipient.strip().lower()}"
        existing = session.query(EmailOutbox).filter_by(deduplication_key=dedup_key).first()
        if existing:
            continue

        subject, text_body, html_body = EmailService.build_advisory_email(event, advisory)

        outbox_entry = EmailOutbox(
            event_id=event.id,
            recipient=recipient.strip(),
            subject=subject,
            body=text_body,
            body_html=html_body,
            status="PENDING",
            attempts=0,
            next_attempt_at=datetime.datetime.utcnow(),
            deduplication_key=dedup_key
        )
        session.add(outbox_entry)
        enqueued += 1

    session.flush()
    if enqueued > 0:
        logger.info(f"Enqueued {enqueued} notification emails in outbox.")
    return enqueued

def process_outbox(session: Session, max_batch: int = 10, max_attempts: int = 5) -> int:
    """
    Processes pending outbox emails.
    Implements durable retry with exponential backoff.
    Never marks SENT unless SMTP server accepts delivery.
    """
    now = datetime.datetime.utcnow()
    pending_items = (
        session.query(EmailOutbox)
        .filter(
            EmailOutbox.status.in_(["PENDING", "FAILED"]),
            EmailOutbox.attempts < max_attempts,
            EmailOutbox.next_attempt_at <= now
        )
        .order_by(EmailOutbox.created_at.asc())
        .limit(max_batch)
        .all()
    )

    if not pending_items:
        return 0

    sent_count = 0
    for item in pending_items:
        item.attempts += 1
        try:
            EmailService.send_raw_email(
                recipient=item.recipient,
                subject=item.subject,
                text_body=item.body,
                html_body=item.body_html
            )
            item.status = "SENT"
            item.sent_at = datetime.datetime.utcnow()
            item.last_error = None
            sent_count += 1
            logger.info(f"Outbox email #{item.id} successfully sent to {item.recipient}")
        except Exception as exc:
            err_msg = str(exc)
            item.status = "FAILED"
            item.last_error = err_msg
            # Exponential backoff: 2m, 4m, 8m, 16m...
            backoff_minutes = 2 ** item.attempts
            item.next_attempt_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=backoff_minutes)
            logger.warning(
                f"Failed delivering email #{item.id} (attempt {item.attempts}/{max_attempts}): {err_msg}. "
                f"Next attempt at {item.next_attempt_at.isoformat()}."
            )

    session.flush()
    return sent_count
