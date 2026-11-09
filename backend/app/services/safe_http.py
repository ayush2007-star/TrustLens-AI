import http.client
import socket
import ssl
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional

from app.config import settings
from app.services.ssrf_guard import SSRFSecurityError, is_safe_port, validate_target_host


@dataclass
class SafeHTTPResponse:
    status_code: int
    headers: Dict[str, str]
    set_cookie_headers: List[str]
    body: bytes
    truncated: bool = False


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def safe_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    max_bytes: Optional[int] = None,
) -> SafeHTTPResponse:
    """Make one HTTP request, pinning the socket to a validated public DNS answer."""
    response_limit = max_bytes if max_bytes is not None else settings.MAX_RESPONSE_BYTES
    if isinstance(response_limit, bool) or not isinstance(response_limit, int) or response_limit < 1:
        raise ValueError("max_bytes must be a positive integer.")

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SSRFSecurityError("Only absolute HTTP and HTTPS target URLs are allowed.")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFSecurityError("Target URLs containing user information are not allowed.")

    method_name = method.upper()
    if method_name not in {"GET", "HEAD"}:
        raise SSRFSecurityError("Only GET and HEAD are permitted for passive inspection requests.")

    hostname = parsed.hostname.rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not is_safe_port(parsed.scheme, port):
        raise SSRFSecurityError(
            f"Non-standard port {port} is not allowed for passive inspection; only the standard HTTP/HTTPS ports 80 and 443 may be contacted."
        )

    is_safe, message, addresses = validate_target_host(hostname)
    if not is_safe:
        raise SSRFSecurityError(message)

    request_path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if port != (443 if parsed.scheme == "https" else 80):
        host_header = f"{host_header}:{port}"

    if headers:
        for key in headers:
            if key.lower() in {"host", "connection", "content-length"}:
                raise SSRFSecurityError(f"Security-critical header '{key}' cannot be overridden for passive checks.")

    request_headers = {"Host": host_header, "Connection": "close"}
    request_headers.update(headers or {})
    last_error: Optional[Exception] = None
    for address in addresses:
        connection: Optional[http.client.HTTPConnection] = None
        try:
            connection_type = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
            connection = connection_type(hostname, port, address, settings.REQUEST_TIMEOUT_SECONDS)
            connection.request(method_name, request_path, headers=request_headers)
            response = connection.getresponse()

            response_body = response.read(response_limit + 1)
            truncated = len(response_body) > response_limit
            body = response_body[:response_limit]

            response_headers = {key.lower(): value for key, value in response.getheaders()}
            set_cookie_headers = response.headers.get_all("Set-Cookie", [])
            return SafeHTTPResponse(response.status, response_headers, set_cookie_headers, body, truncated)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            if connection is not None:
                connection.close()

    if last_error:
        raise last_error
    raise SSRFSecurityError("No validated public address was available for the target.")
