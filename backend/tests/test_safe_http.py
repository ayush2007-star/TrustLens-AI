from email.message import Message

import pytest

from app.services.safe_http import safe_request


def test_safe_request_connects_to_validated_ip(monkeypatch):
    observed = {}

    class FakeResponse:
        status = 200

        def __init__(self):
            self.headers = Message()
            self.headers["X-Test"] = "present"

        def getheaders(self):
            return self.headers.items()

        def read(self, limit):
            return b"body"

    class FakeConnection:
        def __init__(self, host, port, address, timeout):
            observed.update(host=host, port=port, address=address)

        def request(self, method, path, headers):
            observed.update(method=method, path=path, headers=headers)

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        "app.services.safe_http.validate_target_host",
        lambda host: (True, "", ["8.8.8.8"]),
    )
    monkeypatch.setattr("app.services.safe_http._PinnedHTTPConnection", FakeConnection)

    response = safe_request("GET", "http://example.test/a?b=c")

    assert observed["host"] == "example.test"
    assert observed["address"] == "8.8.8.8"
    assert observed["path"] == "/a?b=c"
    assert observed["headers"]["Host"] == "example.test"
    assert response.status_code == 200
    assert response.body == b"body"


def test_safe_request_rejects_non_http_schemes():
    import pytest

    from app.services.ssrf_guard import SSRFSecurityError

    with pytest.raises(SSRFSecurityError):
        safe_request("GET", "file:///etc/passwd")


def test_safe_request_rejects_non_standard_ports():
    import pytest

    from app.services.ssrf_guard import SSRFSecurityError

    with pytest.raises(SSRFSecurityError, match="standard.*port|80|443"):
        safe_request("GET", "https://example.test:8443/")


def test_safe_request_rejects_unsafe_method_names():
    from app.services.ssrf_guard import SSRFSecurityError

    with pytest.raises(SSRFSecurityError, match="GET|HEAD"):
        safe_request("POST", "https://example.test/")


@pytest.mark.parametrize(
    ("body", "expected_body", "expected_truncated"),
    [
        (b"1234", b"1234", False),
        (b"12345", b"1234", True),
    ],
)
def test_safe_request_reads_one_byte_past_limit(
    monkeypatch, body, expected_body, expected_truncated
):
    observed = {}

    class FakeResponse:
        status = 200

        def __init__(self):
            self.headers = Message()

        def getheaders(self):
            return self.headers.items()

        def read(self, limit):
            observed["read_limit"] = limit
            return body[:limit]

    class FakeConnection:
        def __init__(self, *args):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        "app.services.safe_http.validate_target_host",
        lambda host: (True, "", ["8.8.8.8"]),
    )
    monkeypatch.setattr("app.services.safe_http._PinnedHTTPConnection", FakeConnection)

    response = safe_request("GET", "http://example.test", max_bytes=4)

    assert observed["read_limit"] == 5
    assert response.body == expected_body
    assert response.truncated is expected_truncated


@pytest.mark.parametrize("max_bytes", [0, -1, 1.5, True])
def test_safe_request_rejects_invalid_response_limits(max_bytes):
    with pytest.raises(ValueError, match="positive integer"):
        safe_request("GET", "http://example.test", max_bytes=max_bytes)
