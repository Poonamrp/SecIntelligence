import json
import datetime
from typing import List, Tuple, Dict, Any, Optional
from sqlalchemy.orm import Session
from src.models import Advisory, AdvisoryEvent, Source, Setting
from src.services.normalize import NormalizedAdvisory
from src.services.fingerprint import compute_content_hash, detect_changes
from src.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger("change_detection")

def is_baseline_mode(session: Session) -> bool:
    """Checks whether baseline mode is currently active."""
    setting = session.query(Setting).filter_by(key="baseline_mode").first()
    if setting:
        try:
            return bool(json.loads(setting.value_json))
        except Exception:
            pass
    return get_config().baseline_mode

def set_baseline_mode(session: Session, enabled: bool) -> None:
    """Updates baseline mode state in database."""
    setting = session.query(Setting).filter_by(key="baseline_mode").first()
    if not setting:
        setting = Setting(key="baseline_mode", value_json=json.dumps(enabled))
        session.add(setting)
    else:
        setting.value_json = json.dumps(enabled)
        setting.updated_at = datetime.datetime.utcnow()
    session.flush()
    logger.info(f"Baseline mode set to: {enabled}")

def process_collected_advisories(
    session: Session,
    source: Source,
    advisories: List[NormalizedAdvisory],
    override_baseline: Optional[bool] = None
) -> Tuple[int, int, List[AdvisoryEvent]]:
    """
    Core change detection engine.
    Ingests normalized advisories, calculates deterministic fingerprints,
    updates database records, and creates events for genuine additions/changes.
    
    Returns:
        (records_new, records_updated, list_of_created_events)
    """
    baseline_active = override_baseline if override_baseline is not None else is_baseline_mode(session)
    records_new = 0
    records_updated = 0
    created_events: List[AdvisoryEvent] = []
    now = datetime.datetime.utcnow()

    for adv in advisories:
        content_hash = compute_content_hash(
            title=adv.title,
            description=adv.description,
            severity=adv.severity,
            cvss_score=adv.cvss_score,
            cvss_vector=adv.cvss_vector,
            affected_products=adv.affected_products,
            references=adv.references,
            is_kev=adv.is_kev,
            zero_day_status=adv.zero_day_status
        )

        existing = session.query(Advisory).filter_by(stable_key=adv.stable_key).first()

        if existing is None:
            # Also check if matching CVE ID exists under another stable key
            if adv.cve_id:
                existing = session.query(Advisory).filter_by(cve_id=adv.cve_id).first()

        if existing is None:
            # Case 1: Brand new advisory
            new_record = Advisory(
                stable_key=adv.stable_key,
                cve_id=adv.cve_id,
                ghsa_id=adv.ghsa_id,
                source_id=source.id if source else None,
                title=adv.title,
                summary=adv.summary,
                description=adv.description,
                canonical_url=adv.canonical_url,
                published_at=adv.published_at or now,
                modified_at=adv.modified_at or now,
                severity=adv.severity,
                cvss_score=adv.cvss_score,
                cvss_version=adv.cvss_version,
                cvss_vector=adv.cvss_vector,
                affected_products_json=json.dumps(adv.affected_products),
                references_json=json.dumps(adv.references),
                is_kev=adv.is_kev,
                kev_date_added=adv.kev_date_added,
                zero_day_status=adv.zero_day_status,
                zero_day_evidence_url=adv.zero_day_evidence_url,
                first_seen_at=now,
                last_seen_at=now,
                content_hash=content_hash,
                raw_data_json=json.dumps(adv.raw_data) if adv.raw_data else None
            )
            session.add(new_record)
            session.flush()
            records_new += 1

            if not baseline_active:
                event_type = "NEW"
                if adv.is_kev:
                    event_type = "KEV_ADDED"
                elif adv.zero_day_status == "CONFIRMED_ZERO_DAY":
                    event_type = "ZERO_DAY_CONFIRMED"

                event = AdvisoryEvent(
                    advisory_id=new_record.id,
                    event_type=event_type,
                    old_hash=None,
                    new_hash=content_hash,
                    changes_json=json.dumps({"initial": "New advisory registered"}),
                    detected_at=now
                )
                session.add(event)
                session.flush()
                created_events.append(event)

        else:
            # Case 2: Existing advisory found
            existing.last_seen_at = now

            # If content hash identical, no meaningful change occurred (ignore fetch time)
            if existing.content_hash == content_hash:
                continue

            # Content hash changed; pinpoint what changed
            has_changed, changes = detect_changes(existing, adv)
            if not has_changed:
                # No tracked fields changed, simply update content hash
                existing.content_hash = content_hash
                continue

            old_hash = existing.content_hash
            records_updated += 1

            # Determine event type
            if "is_kev" in changes and changes["is_kev"]["new"] is True:
                event_type = "KEV_ADDED"
            elif "zero_day_status" in changes and changes["zero_day_status"]["new"] == "CONFIRMED_ZERO_DAY":
                event_type = "ZERO_DAY_CONFIRMED"
            else:
                event_type = "UPDATED"

            # Update existing record fields
            if adv.is_kev:
                existing.is_kev = True
                if adv.kev_date_added:
                    existing.kev_date_added = adv.kev_date_added
                elif not existing.kev_date_added:
                    existing.kev_date_added = now

            # Update existing record fields
            existing.title = adv.title
            if adv.description:
                existing.description = adv.description
            if adv.summary:
                existing.summary = adv.summary
            existing.severity = adv.severity
            if adv.cvss_score is not None:
                existing.cvss_score = adv.cvss_score
                existing.cvss_version = adv.cvss_version
                existing.cvss_vector = adv.cvss_vector
            if adv.affected_products:
                existing.affected_products_json = json.dumps(adv.affected_products)
            if adv.references:
                existing.references_json = json.dumps(adv.references)
            existing.zero_day_status = adv.zero_day_status
            if adv.zero_day_evidence_url:
                existing.zero_day_evidence_url = adv.zero_day_evidence_url
            existing.modified_at = adv.modified_at or now
            existing.content_hash = content_hash

            if not baseline_active:
                event = AdvisoryEvent(
                    advisory_id=existing.id,
                    event_type=event_type,
                    old_hash=old_hash,
                    new_hash=content_hash,
                    changes_json=json.dumps(changes),
                    detected_at=now
                )
                session.add(event)
                session.flush()
                created_events.append(event)

    return records_new, records_updated, created_events
