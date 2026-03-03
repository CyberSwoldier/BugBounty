import requests
import urllib3
from typing import Optional, Dict, Any
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

class HTTPClient:
    def __init__(self, timeout: int = 10, retries: int = 2, delay: float = 0.3):
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.session.verify = False

    def get(self, url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None) -> Optional[requests.Response]:
        for attempt in range(self.retries):
            try:
                time.sleep(self.delay)
                resp = self.session.get(url, headers=headers, params=params, timeout=self.timeout, allow_redirects=True)
                return resp
            except Exception:
                if attempt == self.retries - 1:
                    return None

    def post(self, url: str, data: Any = None, json: Any = None, headers: Optional[Dict] = None) -> Optional[requests.Response]:
        for attempt in range(self.retries):
            try:
                time.sleep(self.delay)
                resp = self.session.post(url, data=data, json=json, headers=headers, timeout=self.timeout, allow_redirects=True)
                return resp
            except Exception:
                if attempt == self.retries - 1:
                    return None

    def head(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.head(url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None
