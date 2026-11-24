import os
import yaml
import json
import threading
import datetime
from typing import Optional, Dict, Any, List
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

from src.database import get_db_session, init_db
from src.models import Source, CollectionRun, SourceRun, AdvisoryEvent, Setting
from src.collectors import get_collector_for_source
from src.services.change_detection import process_collected_advisories, is_baseline_mode
from src.services.outbox import enqueue_advisory_alerts, process_outbox
from src.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger("scheduler")

# Concurrency lock to prevent overlapping runs
_collection_lock = threading.Lock()
_scheduler: Optional[BackgroundScheduler] = None

def seed_sources_if_empty(session: Session) -> None:
    """Seeds or syncs sources from config/sources.yaml into the database."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "sources.yaml")
    if not os.path.exists(config_path):
        logger.warning(f"Sources config not found at {config_path}")
        return

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        sources_list = data.get("sources", [])
        added_count = 0
        for item in sources_list:
            existing = session.query(Source).filter_by(name=item["name"]).first()
            if not existing:
                src = Source(
                    name=item["name"],
                    source_type=item["type"],
                    url=item["url"],
                    enabled=bool(item.get("enabled", True)),
                    config_json=json.dumps(item.get("config", {})),
                    last_error=None
                )
                session.add(src)
                added_count += 1
        session.flush()
        if added_count > 0:
            logger.info(f"Successfully synced {added_count} new sources into database.")
    except Exception as exc:
        logger.error(f"Failed to seed sources from {config_path}: {exc}", exc_info=True)

def execute_collection_cycle(
    is_manual: bool = False,
    target_source_id: Optional[int] = None
) -> Optional[int]:
    """
    Executes a complete threat intelligence collection cycle.
    Guarantees single-instance execution via lock to prevent overlapping runs.
    Returns the CollectionRun ID if executed, or None if skipped due to concurrency.
    """
    if not _collection_lock.acquire(blocking=False):
        logger.warning("Collection cycle is already actively running. Skipping requested trigger.")
        return None

    run_id = None
    try:
        with get_db_session() as session:
            seed_sources_if_empty(session)
            
            # Create Run record
            run = CollectionRun(
                started_at=datetime.datetime.utcnow(),
                status="RUNNING"
            )
            session.add(run)
            session.flush()
            run_id = run.id

            # Determine sources to query
            query = session.query(Source)
            if target_source_id is not None:
                query = query.filter_by(id=target_source_id)
            else:
                query = query.filter_by(enabled=True)
            
            active_sources = query.all()
            logger.info(f"Starting Collection Run #{run.id} for {len(active_sources)} sources (manual={is_manual})")

            total_seen = 0
            total_new = 0
            total_updated = 0
            errors_count = 0
            all_created_events: List[AdvisoryEvent] = []

            for source in active_sources:
                source_run = SourceRun(
                    run_id=run.id,
                    source_id=source.id,
                    started_at=datetime.datetime.utcnow(),
                    status="RUNNING"
                )
                session.add(source_run)
                session.flush()

                source.last_attempt_at = datetime.datetime.utcnow()

                try:
                    conf = json.loads(source.config_json or "{}")
                    collector = get_collector_for_source(
                        name=source.name,
                        source_type=source.source_type,
                        url=source.url,
                        config=conf
                    )

                    advisories = collector.collect(last_check=source.last_success_at)
                    source_run.records_seen = len(advisories)
                    total_seen += len(advisories)

                    new_count, upd_count, events = process_collected_advisories(
                        session=session,
                        source=source,
                        advisories=advisories
                    )

                    total_new += new_count
                    total_updated += upd_count
                    all_created_events.extend(events)

                    source.last_success_at = datetime.datetime.utcnow()
                    source.last_error = None
                    source_run.status = "SUCCESS"
                    source_run.finished_at = datetime.datetime.utcnow()

                except Exception as exc:
                    err_msg = str(exc)
                    logger.error(f"Error collecting from source '{source.name}': {err_msg}", exc_info=True)
                    source.last_error = err_msg
                    source_run.status = "FAILED"
                    source_run.error_message = err_msg
                    source_run.finished_at = datetime.datetime.utcnow()
                    errors_count += 1

                session.flush()

            # Enqueue outbound notification emails for newly generated events
            if all_created_events and not is_baseline_mode(session):
                enqueue_advisory_alerts(session, all_created_events)

            # Process pending outbox
            process_outbox(session)

            # Complete Run
            run.finished_at = datetime.datetime.utcnow()
            run.records_seen = total_seen
            run.records_new = total_new
            run.records_updated = total_updated
            run.errors_count = errors_count
            if errors_count == 0:
                run.status = "COMPLETED"
            elif errors_count < len(active_sources):
                run.status = "PARTIAL"
            else:
                run.status = "FAILED"
            
            run.summary = f"Processed {len(active_sources)} sources: {total_new} new, {total_updated} updated, {errors_count} errors."
            session.flush()
            logger.info(f"Collection Run #{run.id} finished with status: {run.status}. {run.summary}")

    except Exception as exc:
        logger.error(f"Fatal error in collection cycle: {exc}", exc_info=True)
        if run_id:
            try:
                with get_db_session() as session:
                    r = session.query(CollectionRun).filter_by(id=run_id).first()
                    if r:
                        r.status = "FAILED"
                        r.finished_at = datetime.datetime.utcnow()
                        r.summary = f"Fatal cycle exception: {str(exc)}"
            except Exception:
                pass
    finally:
        _collection_lock.release()

    return run_id

def start_scheduler() -> BackgroundScheduler:
    """Initializes and starts the persistent APScheduler instance."""
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        return _scheduler

    init_db()
    cfg = get_config()
    interval_mins = max(5, cfg.check_interval_minutes)

    _scheduler = BackgroundScheduler(
        timezone=cfg.app_timezone,
        job_defaults={
            "coalesce": True,
            "max_instances": 1,
            "misfire_grace_time": 300
        }
    )

    # Schedule recurring hourly job
    _scheduler.add_job(
        func=execute_collection_cycle,
        trigger=IntervalTrigger(minutes=interval_mins),
        id="hourly_threat_collection",
        name="Hourly Threat Intelligence Collection",
        replace_existing=True,
        kwargs={"is_manual": False}
    )

    _scheduler.start()
    logger.info(f"Background scheduler started. Next run scheduled in {interval_mins} minutes.")
    return _scheduler

def trigger_run_now() -> Optional[int]:
    """Triggers an immediate collection run asynchronously or synchronously."""
    t = threading.Thread(target=execute_collection_cycle, kwargs={"is_manual": True}, daemon=True)
    t.start()
    return None

def is_run_in_progress() -> bool:
    """Checks if a collection run is currently locked and active."""
    return _collection_lock.locked()

def get_scheduler() -> Optional[BackgroundScheduler]:
    global _scheduler
    return _scheduler
