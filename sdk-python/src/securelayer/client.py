from dataclasses import dataclass

try:
    import httpx
except ImportError:
    httpx = None

try:
    import requests
except ImportError:
    requests = None


@dataclass(frozen=True)
class SecureLayerClient:
    gateway_url: str
    timeout_seconds: float = 5.0

    def http_client(self):
        if httpx is not None:
            return httpx.Client(base_url=self.gateway_url, timeout=self.timeout_seconds)
        if requests is not None:
            session = requests.Session()
            return session
        raise RuntimeError("Neither httpx nor requests is installed")

