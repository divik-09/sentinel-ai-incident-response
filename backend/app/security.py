"""Authentication, role-based authorisation, rate limiting and HTTP hardening.

* API keys are never stored: configuration holds ``name:role:sha256(key)``. Comparison is constant-time.
* Roles are ordered ``viewer < operator < approver``. The *principal's* name is what lands in the audit trail;
  clients cannot choose who they are acting as.
* Rate limiting is an in-process token bucket (per principal, and a stricter one per client IP for failed
  authentication). It protects a single instance; behind multiple replicas use a shared limiter at the edge.
"""

from __future__ import annotations

import hmac
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import ROLES, Settings, hash_api_key

ROLE_RANK = {role: index for index, role in enumerate(ROLES)}


@dataclass(frozen=True)
class Principal:
    name: str
    role: str

    def can(self, role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[role]


LOCAL_PRINCIPAL = Principal(name="local-operator", role="approver")


class TokenBucket:
    def __init__(self, per_minute: int, burst: int | None = None, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000):
        self.rate = per_minute / 60.0
        self.capacity = float(burst if burst is not None else max(per_minute, 1))
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def check(self, key: str) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds)."""
        if self.rate <= 0:
            return True, 0.0
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                allowed, retry = True, 0.0
            else:
                self._buckets[key] = (tokens, now)
                allowed, retry = False, (1.0 - tokens) / self.rate
            if len(self._buckets) > self._max_keys:  # bound memory under key-spraying
                oldest = sorted(self._buckets.items(), key=lambda kv: kv[1][1])[: self._max_keys // 10]
                for k, _ in oldest:
                    self._buckets.pop(k, None)
        return allowed, retry


class Authenticator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.limiter = TokenBucket(settings.rate_limit_per_minute) if settings.rate_limit_per_minute else None
        self.fail_limiter = TokenBucket(10, burst=10)  # 10 failed attempts per minute per IP

    @staticmethod
    def _extract(request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            return header[7:].strip() or None
        return request.headers.get("x-api-key") or None

    def authenticate(self, request: Request) -> Principal:
        client = request.client.host if request.client else "unknown"
        if not self.settings.auth_enabled:
            principal = LOCAL_PRINCIPAL
        else:
            raw = self._extract(request)
            found: Principal | None = None
            if raw:
                digest = hash_api_key(raw)
                for entry in self.settings.api_keys:  # iterate all entries: no early exit on match
                    if hmac.compare_digest(entry.sha256, digest):
                        found = Principal(entry.name, entry.role)
            if found is None:
                allowed, retry = self.fail_limiter.check(f"fail:{client}")
                if not allowed:
                    raise HTTPException(429, "Too many failed authentication attempts", headers={"Retry-After": str(int(retry) + 1)})
                raise HTTPException(401, "Missing or invalid API key", headers={"WWW-Authenticate": "Bearer"})
            principal = found
        if self.limiter:
            ok, retry_after = self.limiter.check(f"p:{principal.name}")
            if not ok:
                raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": str(int(retry_after) + 1)})
        request.state.principal = principal
        return principal

    def require(self, role: str) -> Callable[[Request], Principal]:
        def dependency(request: Request) -> Principal:
            principal = self.authenticate(request)
            if not principal.can(role):
                raise HTTPException(403, f"This action requires the '{role}' role")
            return principal

        return dependency


# --------------------------------------------------------------------------- ASGI middleware
class BodyLimitMiddleware:
    """Rejects oversized request bodies (declared or streamed) with 413 before they reach the app."""

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        started = False

        async def reject() -> None:
            body = b'{"detail":"Request body too large"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
                }
            )
            await send({"type": "http.response.body", "body": body})

        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            await reject()
            return

        received = 0

        class _TooLarge(Exception):
            pass

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _TooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await reject()


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
}


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, hsts: bool = False):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_docs = path.startswith(("/docs", "/redoc", "/openapi"))

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {k.lower() for k, _ in headers}
                for key, value in SECURITY_HEADERS.items():
                    if key == "Content-Security-Policy" and is_docs:
                        continue  # Swagger UI loads CDN assets and inline scripts
                    if key.lower().encode() not in existing:
                        headers.append((key.lower().encode(), value.encode()))
                if path.startswith("/api") or path == "/metrics":
                    headers.append((b"cache-control", b"no-store"))
                if self.hsts:
                    headers.append((b"strict-transport-security", b"max-age=63072000; includeSubDomains"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, wrapped)
