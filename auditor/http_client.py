from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# Perfiles de User-Agent para auditar comportamiento dependiente del cliente
# (por ejemplo cloaking que sirve contenido distinto a movil, escritorio o bots).
UA_PROFILES: dict[str, str] = {
    "auditor": "Auditor/0.1 authorized-security-audit",
    "desktop": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "mobile": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
        "Mobile/15E148 Safari/604.1"
    ),
    "googlebot": (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ),
}


@dataclass
class HttpResponse:
    url: str
    final_url: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed: float = 0.0
    error: str = ""

    @property
    def text(self) -> str:
        content_type = self.headers.get("content-type", "")
        encoding = "utf-8"
        if "charset=" in content_type:
            encoding = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
        return self.body.decode(encoding or "utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


class SafeHttpClient:
    def __init__(
        self,
        timeout: float = 10.0,
        rate_limit: float = 1.0,
        user_agent: str = "Auditor/0.1 authorized-security-audit",
    ) -> None:
        self.timeout = timeout
        self.rate_limit = max(rate_limit, 0.0)
        self.user_agent = user_agent
        self._last_request_at = 0.0

    def fetch(
        self,
        url: str,
        method: str = "GET",
        max_bytes: int = 1_000_000,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        self._throttle()
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8",
        }
        if headers:
            request_headers.update(headers)

        request = Request(url, headers=request_headers, method=method.upper())
        start = time.monotonic()
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = b"" if method.upper() == "HEAD" else response.read(max_bytes)
                elapsed = time.monotonic() - start
                return HttpResponse(
                    url=url,
                    final_url=response.geturl(),
                    status_code=response.status,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=body,
                    elapsed=elapsed,
                )
        except HTTPError as exc:
            body = b"" if method.upper() == "HEAD" else exc.read(max_bytes)
            elapsed = time.monotonic() - start
            return HttpResponse(
                url=url,
                final_url=exc.url,
                status_code=exc.code,
                headers={k.lower(): v for k, v in exc.headers.items()},
                body=body,
                elapsed=elapsed,
                error=str(exc),
            )
        except (URLError, TimeoutError, OSError) as exc:
            elapsed = time.monotonic() - start
            return HttpResponse(
                url=url,
                final_url=url,
                status_code=None,
                elapsed=elapsed,
                error=str(exc),
            )

    def _throttle(self) -> None:
        if self.rate_limit <= 0:
            return
        wait_seconds = self.rate_limit - (time.monotonic() - self._last_request_at)
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        self._last_request_at = time.monotonic()

