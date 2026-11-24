import re
from typing import Optional, Tuple

ZERO_DAY_KEYWORDS = [
    r'\bzero-day\b',
    r'\b0-day\b',
    r'\bzero day\b',
    r'\bactively exploited\b',
    r'\bin the wild\b',
    r'\bexploited in the wild\b',
    r'\bunder active exploitation\b'
]
ZERO_DAY_PATTERN = re.compile('|'.join(ZERO_DAY_KEYWORDS), re.IGNORECASE)

def classify_severity(
    cvss_score: Optional[float] = None,
    explicit_label: Optional[str] = None
) -> Tuple[str, Optional[float]]:
    """
    Classifies vulnerability severity based on CVSS base score (v3/v4/v2)
    or explicit source label.
    
    Rules:
      Critical: CVSS >= 9.0 or explicit label Critical
      High: CVSS 7.0 - 8.9 or explicit label High
      Medium: CVSS 4.0 - 6.9 or explicit label Medium
      Low: CVSS > 0.0 and < 4.0 or explicit label Low
      Unknown: When no valid score or recognizable label is present.
    """
    valid_score = None
    if cvss_score is not None:
        try:
            s = float(cvss_score)
            if 0.0 <= s <= 10.0:
                valid_score = round(s, 1)
        except (ValueError, TypeError):
            valid_score = None

    if valid_score is not None and valid_score > 0:
        if valid_score >= 9.0:
            return "Critical", valid_score
        elif valid_score >= 7.0:
            return "High", valid_score
        elif valid_score >= 4.0:
            return "Medium", valid_score
        elif valid_score > 0.0:
            return "Low", valid_score

    # Fallback to explicit label if score not provided or 0
    if explicit_label and isinstance(explicit_label, str):
        label_clean = explicit_label.strip().upper()
        if "CRITICAL" in label_clean:
            return "Critical", valid_score
        elif "HIGH" in label_clean or "IMPORTANT" in label_clean:
            return "High", valid_score
        elif "MEDIUM" in label_clean or "MODERATE" in label_clean:
            return "Medium", valid_score
        elif "LOW" in label_clean:
            return "Low", valid_score

    return "Unknown", valid_score

def assess_zero_day(
    text: Optional[str],
    has_confirmed_evidence: bool = False,
    evidence_url: Optional[str] = None
) -> Tuple[str, Optional[str]]:
    """
    Evaluates zero-day status.
    
    CRITICAL RULE:
    - Never infer confirmed zero-day solely from keyword search!
    - Keywords like 'zero-day', '0-day', or 'in the wild' without verified authoritative
      confirmation are marked as 'UNVERIFIED_SIGNAL' (Needs review).
    - 'CONFIRMED_ZERO_DAY' requires verified evidence URL and confirmed flag.
    """
    if has_confirmed_evidence and evidence_url:
        return "CONFIRMED_ZERO_DAY", evidence_url

    if text and ZERO_DAY_PATTERN.search(text):
        return "UNVERIFIED_SIGNAL", evidence_url

    return "NONE", None
