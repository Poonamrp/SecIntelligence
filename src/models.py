import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from src.database import Base

class Source(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    source_type = Column(String(50), nullable=False)  # 'api', 'rss', 'html'
    url = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    config_json = Column(Text, nullable=True)  # JSON dictionary for optional parameters
    last_attempt_at = Column(DateTime, nullable=True)
    last_success_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    advisories = relationship("Advisory", back_populates="source", cascade="all, delete-orphan")
    runs = relationship("SourceRun", back_populates="source", cascade="all, delete-orphan")

class Advisory(Base):
    __tablename__ = "advisories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    stable_key = Column(String(255), unique=True, nullable=False, index=True)  # CVE-202X-XXXX or GHSA-XXXX or SHA256(url)
    cve_id = Column(String(50), nullable=True, index=True)
    ghsa_id = Column(String(50), nullable=True, index=True)
    source_id = Column(Integer, ForeignKey("sources.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    canonical_url = Column(Text, nullable=False)
    published_at = Column(DateTime, nullable=True, index=True)
    modified_at = Column(DateTime, nullable=True)
    
    # Severity classification: Critical, High, Medium, Low, Unknown
    severity = Column(String(20), default="Unknown", nullable=False, index=True)
    cvss_score = Column(Float, nullable=True, index=True)
    cvss_version = Column(String(10), nullable=True)  # '2.0', '3.0', '3.1', '4.0'
    cvss_vector = Column(String(100), nullable=True)
    
    affected_products_json = Column(Text, nullable=True)  # JSON array of affected products/packages
    references_json = Column(Text, nullable=True)         # JSON array of reference URLs
    
    # KEV (Known Exploited Vulnerability)
    is_kev = Column(Boolean, default=False, nullable=False, index=True)
    kev_date_added = Column(DateTime, nullable=True)
    
    # Zero-day status: NONE, UNVERIFIED_SIGNAL, CONFIRMED_ZERO_DAY
    zero_day_status = Column(String(50), default="NONE", nullable=False, index=True)
    zero_day_evidence_url = Column(Text, nullable=True)
    
    first_seen_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    content_hash = Column(String(64), nullable=False)
    raw_data_json = Column(Text, nullable=True)

    source = relationship("Source", back_populates="advisories")
    events = relationship("AdvisoryEvent", back_populates="advisory", cascade="all, delete-orphan")

class AdvisoryEvent(Base):
    __tablename__ = "advisory_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    advisory_id = Column(Integer, ForeignKey("advisories.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # 'NEW', 'UPDATED', 'KEV_ADDED', 'ZERO_DAY_CONFIRMED'
    old_hash = Column(String(64), nullable=True)
    new_hash = Column(String(64), nullable=False)
    changes_json = Column(Text, nullable=True)  # JSON map of changed fields
    detected_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)

    advisory = relationship("Advisory", back_populates="events")
    outbox_emails = relationship("EmailOutbox", back_populates="event", cascade="all, delete-orphan")

class EmailOutbox(Base):
    __tablename__ = "email_outbox"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("advisory_events.id", ondelete="SET NULL"), nullable=True, index=True)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    body_html = Column(Text, nullable=True)
    status = Column(String(20), default="PENDING", nullable=False, index=True)  # 'PENDING', 'SENT', 'FAILED'
    attempts = Column(Integer, default=0, nullable=False)
    next_attempt_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    sent_at = Column(DateTime, nullable=True)
    deduplication_key = Column(String(255), unique=True, nullable=False, index=True)

    event = relationship("AdvisoryEvent", back_populates="outbox_emails")

class CollectionRun(Base):
    __tablename__ = "collection_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="RUNNING", nullable=False)  # 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL'
    records_seen = Column(Integer, default=0, nullable=False)
    records_new = Column(Integer, default=0, nullable=False)
    records_updated = Column(Integer, default=0, nullable=False)
    errors_count = Column(Integer, default=0, nullable=False)
    summary = Column(Text, nullable=True)

    source_runs = relationship("SourceRun", back_populates="run", cascade="all, delete-orphan")

class SourceRun(Base):
    __tablename__ = "source_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("collection_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    source_id = Column(Integer, ForeignKey("sources.id", ondelete="CASCADE"), nullable=False, index=True)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="RUNNING", nullable=False)  # 'RUNNING', 'SUCCESS', 'FAILED', 'SKIPPED'
    records_seen = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)
    http_status = Column(Integer, nullable=True)

    run = relationship("CollectionRun", back_populates="source_runs")
    source = relationship("Source", back_populates="runs")

class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
