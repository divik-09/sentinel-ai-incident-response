"""Minimal OpenAI-compatible chat client with timeouts, bounded retries and a circuit breaker.

The transport is injectable so the whole LLM path can be tested offline with ``httpx.MockTransport``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx

log = logging.getLogger("sentinel.llm")


class LLMUnavailable(RuntimeError):
    """Raised when the model endpoint cannot be used (error, timeout, or breaker open)."""


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, reset_seconds: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if self._clock() - self._opened_at >= self.reset_seconds:
                self._opened_at = None  # half-open: allow one trial request
                self._failures = self.failure_threshold - 1
                return True
            return False

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = self._clock()

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._opened_at is not None


class LLMClient:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        timeout: float = 18.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.4,
        transport: httpx.BaseTransport | None = None,
        breaker: CircuitBreaker | None = None,
        sleep: Callable[[float], None] = time.sleep,
        on_event: Callable[[str], None] | None = None,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.breaker = breaker or CircuitBreaker()
        self._sleep = sleep
        self._on_event = on_event or (lambda _outcome: None)
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def close(self) -> None:
        self._http.close()

    def chat(self, body: dict[str, Any]) -> dict[str, Any]:
        if not self.breaker.allow():
            self._on_event("breaker_open")
            raise LLMUnavailable("circuit breaker open")
        last_error = "unknown"
        for attempt in range(self.max_retries + 1):
            try:
                response = self._http.post(
                    f"{self.base_url}/chat/completions",
                    json=body,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                if response.status_code in (429, 500, 502, 503, 504):
                    last_error = f"http {response.status_code}"
                elif response.status_code >= 400:
                    self.breaker.failure()
                    self._on_event("client_error")
                    raise LLMUnavailable(f"http {response.status_code}")
                else:
                    payload = response.json()
                    if not isinstance(payload, dict):
                        raise ValueError("unexpected response shape")
                    self.breaker.success()
                    self._on_event("ok")
                    return payload
            except (httpx.TransportError, ValueError) as exc:
                last_error = type(exc).__name__
            if attempt < self.max_retries:
                self._sleep(self.backoff_seconds * (2**attempt))
        self.breaker.failure()
        self._on_event("failed")
        log.warning("llm request failed after retries: %s", last_error)
        raise LLMUnavailable(last_error)
