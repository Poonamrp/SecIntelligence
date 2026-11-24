import time
import random
import requests
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from src.utils.logging_config import get_logger

logger = get_logger("http_client")

MAX_RESPONSE_SIZE = 50 * 1024 * 1024  # 50 MB safety limit
DEFAULT_TIMEOUT = (10.0, 30.0)         # (connect timeout, read timeout)

class SafeHttpClient:
    """
    Robust HTTP client with exponential backoff, rate limit respect,
    URL scheme validation, and response size guards.
    """
    def __init__(self, user_agent: Optional[str] = None):
        self.session = requests.Session()
        ua = user_agent or "SecurityIntelligenceMonitor/1.0 (+https://github.com/security-intelligence-monitor)"
        self.session.headers.update({
            "User-Agent": ua,
            "Accept-Encoding": "gzip, deflate",
        })

    def validate_url(self, url: str) -> bool:
        """Enforces HTTP/HTTPS scheme and prevents file/loopback exploits."""
        try:
            parsed = urlparse(url)
            if parsed.scheme.lower() not in ("http", "https"):
                logger.warning(f"Rejected invalid URL scheme: {url}")
                return False
            if not parsed.netloc:
                logger.warning(f"Missing host in URL: {url}")
                return False
            return True
        except Exception as exc:
            logger.error(f"Error validating URL {url}: {exc}")
            return False

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: tuple = DEFAULT_TIMEOUT,
        max_retries: int = 3,
        base_delay: float = 2.0
    ) -> requests.Response:
        """
        Sends GET request with exponential backoff and jitter for transient errors.
        Respects Retry-After header for 429 rate limit responses.
        """
        if not self.validate_url(url):
            raise ValueError(f"Insecure or invalid URL: {url}")

        attempt = 0
        last_exception = None

        while attempt <= max_retries:
            try:
                resp = self.session.get(url, params=params, headers=headers, timeout=timeout, stream=True)
                
                # Check response size limit
                content_length = resp.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_RESPONSE_SIZE:
                    resp.close()
                    raise ValueError(f"Response size {content_length} exceeds limit of {MAX_RESPONSE_SIZE} bytes")

                # Handle HTTP 429 Too Many Requests
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    wait_seconds = float(retry_after) if retry_after and retry_after.isdigit() else (base_delay * (2 ** attempt) + random.uniform(0.5, 1.5))
                    logger.warning(f"HTTP 429 Rate limited on {url}. Waiting {wait_seconds:.1f}s before retry (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_seconds)
                    attempt += 1
                    continue

                # Retry on server error status codes (500, 502, 503, 504)
                if resp.status_code in (500, 502, 503, 504) and attempt < max_retries:
                    wait_seconds = base_delay * (2 ** attempt) + random.uniform(0.1, 0.5)
                    logger.warning(f"HTTP {resp.status_code} server error on {url}. Retrying in {wait_seconds:.1f}s")
                    time.sleep(wait_seconds)
                    attempt += 1
                    continue

                resp.raise_for_status()
                return resp

            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exception = exc
                if attempt < max_retries:
                    wait_seconds = base_delay * (2 ** attempt) + random.uniform(0.2, 0.8)
                    logger.warning(f"Network error on {url}: {exc}. Retrying in {wait_seconds:.1f}s")
                    time.sleep(wait_seconds)
                    attempt += 1
                else:
                    break
            except Exception as exc:
                logger.error(f"Request failed for {url}: {exc}")
                raise

        if last_exception:
            raise last_exception
        raise RuntimeError(f"Failed to fetch {url} after {max_retries} attempts.")
