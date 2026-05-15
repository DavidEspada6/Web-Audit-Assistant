from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from time import perf_counter

from .models import Header, HttpResponse
from .scope import ScopePolicy


class HttpClientError(RuntimeError):
    pass


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


class HttpClient:
    def __init__(
        self,
        scope: ScopePolicy,
        timeout: float = 10.0,
        delay: float = 0.0,
        max_body_bytes: int = 250_000,
        user_agent: str = "web-audit-assistant/0.1 authorized-security-audit",
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.delay = delay
        self.max_body_bytes = max_body_bytes
        self.user_agent = user_agent
        self._opener = urllib.request.build_opener(NoRedirectHandler)
        self._last_request_at = 0.0

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        if not self.scope.is_allowed_url(url):
            raise HttpClientError(f"URL is outside the configured scope: {url}")

        self._wait_if_needed()

        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if headers:
            request_headers.update(headers)

        request = urllib.request.Request(url, headers=request_headers, method=method)
        started = perf_counter()

        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(self.max_body_bytes)
                elapsed_ms = (perf_counter() - started) * 1000
                return HttpResponse(
                    url=response.geturl(),
                    status=response.status,
                    reason=response.reason,
                    headers=extract_headers(response.headers),
                    body=decode_body(body, response.headers),
                    elapsed_ms=elapsed_ms,
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(self.max_body_bytes)
            elapsed_ms = (perf_counter() - started) * 1000
            return HttpResponse(
                url=url,
                status=exc.code,
                reason=exc.reason,
                headers=extract_headers(exc.headers),
                body=decode_body(body, exc.headers),
                elapsed_ms=elapsed_ms,
            )
        except urllib.error.URLError as exc:
            raise HttpClientError(f"Request failed for {url}: {exc}") from exc

    def _wait_if_needed(self) -> None:
        if self.delay <= 0:
            return
        now = time.monotonic()
        wait_for = self.delay - (now - self._last_request_at)
        if wait_for > 0:
            time.sleep(wait_for)
        self._last_request_at = time.monotonic()


def extract_headers(headers: Message) -> list[Header]:
    return [Header(name=name, value=value) for name, value in headers.items()]


def decode_body(body: bytes, headers: Message) -> str:
    content_type = headers.get("Content-Type", "")
    charset = "utf-8"
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            charset = part.split("=", 1)[1].strip()
            break
    return body.decode(charset, errors="replace")


def join_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    return urllib.parse.urljoin(root, path)

