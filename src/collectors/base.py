import abc
import datetime
from typing import List, Optional, Dict, Any
from src.services.normalize import NormalizedAdvisory
from src.utils.http_client import SafeHttpClient
from src.utils.logging_config import get_logger

class BaseCollector(abc.ABC):
    """Abstract base class for all threat intelligence collectors."""

    def __init__(self, source_name: str, base_url: str, config: Optional[Dict[str, Any]] = None):
        self.source_name = source_name
        self.base_url = base_url
        self.config = config or {}
        self.logger = get_logger(f"collector.{source_name.lower().replace(' ', '_')}")
        self.http_client = SafeHttpClient()

    @abc.abstractmethod
    def collect(self, last_check: Optional[datetime.datetime] = None) -> List[NormalizedAdvisory]:
        """
        Fetches and returns normalized advisories from the source.
        Should only fetch new/modified items since last_check when supported.
        """
        pass

    def test_connection(self) -> Dict[str, Any]:
        """Performs a lightweight probe to verify source accessibility."""
        try:
            resp = self.http_client.get(self.base_url, timeout=(5.0, 10.0), max_retries=1)
            return {
                "success": resp.status_code < 400,
                "status_code": resp.status_code,
                "message": f"Successfully connected (HTTP {resp.status_code})"
            }
        except Exception as exc:
            return {
                "success": False,
                "status_code": None,
                "message": f"Connection failed: {str(exc)}"
            }
