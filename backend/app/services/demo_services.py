from __future__ import annotations

import threading
import uuid
from typing import Any

FAULT_BY_SCENARIO = {
    "payment-pool-exhaustion": ("payments", "database_pool_exhaustion"),
    "inventory-dependency-latency": ("inventory", "supplier_dependency_latency"),
    "orders-schema-mismatch": ("orders", "schema_mismatch"),
    "catalog-cache-stampede": ("catalog", "cache_stampede"),
    "auth-memory-pressure": ("auth", "memory_pressure"),
}

SERVICE_ENDPOINTS = {
    "orders": ["POST /demo/orders"],
    "inventory": ["GET /demo/inventory/stock/{sku}"],
    "payments": ["POST /demo/payments/authorize"],
    "catalog": ["GET /demo/catalog/products"],
    "auth": ["POST /demo/auth/token"],
}


class DemoServiceRuntime:
    """In-process service simulator used to reproduce service-level failure behavior."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._faults: dict[str, str] = {}

    def activate_scenario(self, scenario_id: str) -> None:
        configured = FAULT_BY_SCENARIO.get(scenario_id)
        if not configured:
            return
        service, fault = configured
        with self._lock:
            self._faults[service] = fault

    def reset(self, service: str | None = None) -> None:
        with self._lock:
            if service is None:
                self._faults.clear()
            elif service not in SERVICE_ENDPOINTS:
                raise KeyError("Unknown demo service")
            else:
                self._faults.pop(service, None)

    def statuses(self) -> list[dict[str, Any]]:
        with self._lock:
            faults = dict(self._faults)
        return [
            {
                "service": name,
                "status": "degraded" if name in faults else "healthy",
                "active_fault": faults.get(name),
                "endpoints": SERVICE_ENDPOINTS[name],
            }
            for name in SERVICE_ENDPOINTS
        ]

    def active_fault(self, service: str) -> str | None:
        with self._lock:
            return self._faults.get(service)

    def authorize_payment(self, amount: float, currency: str = "INR") -> tuple[int, dict[str, Any]]:
        if self.active_fault("payments") == "database_pool_exhaustion":
            return 503, {
                "service": "payments",
                "status": "error",
                "error_code": "DB_POOL_TIMEOUT",
                "message": "Timed out waiting to acquire a database connection",
                "retryable": True,
            }
        return 200, {
            "service": "payments",
            "status": "authorized",
            "authorization_id": f"auth-{uuid.uuid4().hex[:10]}",
            "amount": amount,
            "currency": currency,
        }

    def lookup_inventory(self, sku: str, quantity: int = 1) -> tuple[int, dict[str, Any]]:
        if self.active_fault("inventory") == "supplier_dependency_latency":
            return 504, {
                "service": "inventory",
                "status": "error",
                "error_code": "SUPPLIER_GATEWAY_TIMEOUT",
                "message": "Supplier API exceeded the inventory service request budget",
                "simulated_latency_ms": 2780,
                "sku": sku,
            }
        return 200, {
            "service": "inventory",
            "status": "available",
            "sku": sku,
            "requested_quantity": quantity,
            "available_quantity": max(quantity, 25),
        }

    def place_order(self, sku: str, quantity: int, amount: float) -> tuple[int, dict[str, Any]]:
        if self.active_fault("orders") == "schema_mismatch":
            return 500, {
                "service": "orders",
                "status": "error",
                "error_code": "SCHEMA_MISMATCH",
                "message": "Column delivery_instructions does not exist in orders table",
            }
        inventory_status, inventory = self.lookup_inventory(sku, quantity)
        if inventory_status >= 400:
            return 503, {
                "service": "orders",
                "status": "failed",
                "failed_dependency": "inventory",
                "dependency_status": inventory_status,
                "dependency_error": inventory,
            }
        payment_status, payment = self.authorize_payment(amount)
        if payment_status >= 400:
            return 503, {
                "service": "orders",
                "status": "failed",
                "failed_dependency": "payments",
                "dependency_status": payment_status,
                "dependency_error": payment,
            }
        return 201, {
            "service": "orders",
            "status": "created",
            "order_id": f"ord-{uuid.uuid4().hex[:10]}",
            "sku": sku,
            "quantity": quantity,
            "inventory": inventory,
            "payment": payment,
        }

    def list_products(self) -> tuple[int, dict[str, Any]]:
        if self.active_fault("catalog") == "cache_stampede":
            return 200, {
                "service": "catalog",
                "status": "degraded",
                "products": [{"sku": "DEMO-001", "name": "Sentinel Demo Product", "price": 999.0}],
                "cache_hit_rate": 0.08,
                "database_qps": 1850,
                "simulated_latency_ms": 1640,
                "warning": "Cache miss surge is increasing database read pressure.",
            }
        return 200, {
            "service": "catalog",
            "status": "healthy",
            "products": [{"sku": "DEMO-001", "name": "Sentinel Demo Product", "price": 999.0}],
            "cache_hit_rate": 0.94,
            "simulated_latency_ms": 24,
        }

    def issue_token(self, subject: str = "demo-user") -> tuple[int, dict[str, Any]]:
        if self.active_fault("auth") == "memory_pressure":
            return 503, {
                "service": "auth",
                "status": "error",
                "error_code": "WORKER_OOM_RESTART",
                "message": "Authentication worker unavailable during simulated memory pressure",
                "retryable": True,
            }
        return 200, {
            "service": "auth",
            "status": "issued",
            "subject": subject,
            "token": f"demo-token-{uuid.uuid4().hex[:12]}",
        }
