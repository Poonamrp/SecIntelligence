from typing import Optional, Dict, Any
from src.collectors.base import BaseCollector
from src.collectors.nvd import NvdCollector
from src.collectors.cisa_kev import CisaKevCollector
from src.collectors.github_advisories import GitHubAdvisoriesCollector
from src.collectors.rss import RssFeedCollector
from src.collectors.html_listing import HtmlListingCollector
from src.config import get_config

def get_collector_for_source(
    name: str,
    source_type: str,
    url: str,
    config: Optional[Dict[str, Any]] = None
) -> BaseCollector:
    """Factory to create collector instance based on type and name."""
    cfg = get_config()
    conf = config or {}

    name_lower = name.lower()
    source_type_lower = source_type.lower()

    if "cisa kev" in name_lower or "cisa_kev" in name_lower:
        return CisaKevCollector(source_name=name, base_url=url, config=conf)
    
    if "nvd" in name_lower:
        return NvdCollector(source_name=name, base_url=url, config=conf, api_key=cfg.nvd_api_key)
        
    if "github" in name_lower:
        return GitHubAdvisoriesCollector(source_name=name, base_url=url, config=conf, github_token=cfg.github_token)

    if source_type_lower == "rss" or source_type_lower == "atom":
        return RssFeedCollector(source_name=name, base_url=url, config=conf)

    if source_type_lower == "html":
        return HtmlListingCollector(source_name=name, base_url=url, config=conf)

    # Default fallback to RSS if URL ends with xml, rss, atom
    if any(ext in url.lower() for ext in [".xml", ".rss", ".atom", "feed"]):
        return RssFeedCollector(source_name=name, base_url=url, config=conf)

    return RssFeedCollector(source_name=name, base_url=url, config=conf)
