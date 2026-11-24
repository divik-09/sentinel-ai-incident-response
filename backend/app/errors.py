"""Domain errors, mapped to HTTP responses in one place (``main.install_error_handlers``)."""

from __future__ import annotations


class SentinelError(Exception):
    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, **extra: object):
        super().__init__(message)
        self.message = message
        self.extra = extra


class NotFoundError(SentinelError):
    status_code = 404
    code = "not_found"


class ConflictError(SentinelError):
    status_code = 409
    code = "conflict"


class ForbiddenError(SentinelError):
    status_code = 403
    code = "forbidden"


class ValidationFailed(SentinelError):
    status_code = 422
    code = "validation_failed"


class PolicyViolationError(ConflictError):
    code = "policy_violation"

    def __init__(self, violations: list[str]):
        super().__init__("Remediation blocked by policy: " + "; ".join(violations), violations=violations)
        self.violations = violations
