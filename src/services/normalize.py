import re
import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

CVE_REGEX = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
GHSA_REGEX = re.compile(r'\bGHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}\b', re.IGNORECASE)

@dataclass
class NormalizedAdvisory:
    stable_key: str
    source_name: str
    title: str
    canonical_url: str
    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    published_at: Optional[datetime.datetime] = None
    modified_at: Optional[datetime.datetime] = None
    severity: str = "Unknown"
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    cvss_vector: Optional[str] = None
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    is_kev: bool = False
    kev_date_added: Optional[datetime.datetime] = None
    zero_day_status: str = "NONE"  # NONE, UNVERIFIED_SIGNAL, CONFIRMED_ZERO_DAY
    zero_day_evidence_url: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

def extract_cve_id(text: Optional[str]) -> Optional[str]:
    """Extracts first valid CVE-YYYY-NNNN from string."""
    if not text:
        return None
    match = CVE_REGEX.search(text)
    return match.group(0).upper() if match else None

def extract_all_cves(text: Optional[str]) -> List[str]:
    """Extracts all unique CVE IDs from text."""
    if not text:
        return []
    matches = CVE_REGEX.findall(text)
    seen = set()
    res = []
    for m in matches:
        upper = m.upper()
        if upper not in seen:
            seen.add(upper)
            res.append(upper)
    return res

def extract_ghsa_id(text: Optional[str]) -> Optional[str]:
    """Extracts GitHub Security Advisory ID."""
    if not text:
        return None
    match = GHSA_REGEX.search(text)
    return match.group(0).upper() if match else None

def parse_iso_datetime(dt_str: Optional[str]) -> Optional[datetime.datetime]:
    """Parses various ISO 8601 and common date formats into UTC datetime."""
    if not dt_str or not isinstance(dt_str, str):
        return None
    dt_str = dt_str.strip()
    if not dt_str:
        return None
        
    # Replace Z with +00:00 for ISO parsing
    if dt_str.endswith("Z"):
        dt_str = dt_str[:-1] + "+00:00"
        
    try:
        dt = datetime.datetime.fromisoformat(dt_str)
        # Convert to naive UTC if timezone-aware
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        pass
        
    # Common format fallbacks
    common_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S",
        "%d-%m-%Y",
        "%m/%d/%Y"
    ]
    for fmt in common_formats:
        try:
            dt = datetime.datetime.strptime(dt_str, fmt)
            if dt.tzinfo is not None:
                dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            continue
            
    return None
