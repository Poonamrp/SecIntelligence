import hashlib
import json
from typing import Dict, Any, Tuple, Optional
from src.services.normalize import NormalizedAdvisory

def compute_content_hash(
    title: str,
    description: Optional[str],
    severity: str,
    cvss_score: Optional[float],
    cvss_vector: Optional[str],
    affected_products: list,
    references: list,
    is_kev: bool,
    zero_day_status: str
) -> str:
    """
    Computes deterministic SHA-256 content fingerprint.
    Excludes volatile fetch/check timestamps to prevent false updates.
    """
    data = {
        "title": (title or "").strip(),
        "description": (description or "").strip(),
        "severity": (severity or "Unknown").strip().upper(),
        "cvss_score": round(float(cvss_score), 1) if cvss_score is not None else None,
        "cvss_vector": (cvss_vector or "").strip(),
        "affected_products": sorted([str(p).strip() for p in (affected_products or []) if str(p).strip()]),
        "references": sorted([str(r).strip() for r in (references or []) if str(r).strip()]),
        "is_kev": bool(is_kev),
        "zero_day_status": str(zero_day_status).strip().upper()
    }
    encoded = json.dumps(data, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

def detect_changes(existing: Any, new_adv: NormalizedAdvisory) -> Tuple[bool, Dict[str, Any]]:
    """
    Compares existing Advisory DB record with newly collected NormalizedAdvisory.
    Returns (has_changed, changes_dict).
    """
    changes = {}

    def check_diff(field_name: str, old_val: Any, new_val: Any):
        if old_val != new_val:
            changes[field_name] = {"old": old_val, "new": new_val}

    check_diff("title", existing.title, new_adv.title)
    check_diff("severity", existing.severity, new_adv.severity)
    
    # Compare CVSS score rounded
    old_score = round(float(existing.cvss_score), 1) if existing.cvss_score is not None else None
    new_score = round(float(new_adv.cvss_score), 1) if new_adv.cvss_score is not None else None
    check_diff("cvss_score", old_score, new_score)

    check_diff("cvss_vector", existing.cvss_vector, new_adv.cvss_vector)
    check_diff("is_kev", bool(existing.is_kev), bool(new_adv.is_kev))
    check_diff("zero_day_status", existing.zero_day_status, new_adv.zero_day_status)

    # Check parsed lists
    try:
        old_products = sorted(json.loads(existing.affected_products_json or "[]"))
    except Exception:
        old_products = []
    new_products = sorted([str(p).strip() for p in new_adv.affected_products if str(p).strip()])
    check_diff("affected_products", old_products, new_products)

    try:
        old_refs = sorted(json.loads(existing.references_json or "[]"))
    except Exception:
        old_refs = []
    new_refs = sorted([str(r).strip() for r in new_adv.references if str(r).strip()])
    check_diff("references", old_refs, new_refs)

    return (len(changes) > 0), changes
