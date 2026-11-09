import threading
from typing import Any, Callable


DNS_RESOLUTION_TIMEOUT_SECONDS = 3.0
MAX_CONCURRENT_DNS_CALLS = 4

_dns_slots = threading.BoundedSemaphore(MAX_CONCURRENT_DNS_CALLS)


def bounded_dns_call(function: Callable[..., Any], *args: Any, timeout: float = DNS_RESOLUTION_TIMEOUT_SECONDS, **kwargs: Any) -> Any:
    """Run a blocking system resolver call without waiting for it during shutdown."""
    if timeout <= 0:
        raise ValueError("DNS timeout must be greater than zero.")
    if not _dns_slots.acquire(blocking=False):
        raise TimeoutError("DNS resolver capacity is exhausted.")

    completed = threading.Event()
    result: list[Any] = []
    error: list[Exception] = []

    def run() -> None:
        try:
            result.append(function(*args, **kwargs))
        except Exception as exc:
            error.append(exc)
        finally:
            _dns_slots.release()
            completed.set()

    worker = threading.Thread(target=run, daemon=True, name="bounded-dns")
    worker.start()
    if not completed.wait(timeout):
        raise TimeoutError("DNS resolution timed out.")
    if error:
        raise error[0]
    return result[0]
