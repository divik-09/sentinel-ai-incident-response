"""Declarative diagnostic rules.

Each root cause is described as data: a set of weighted *signals*, each of which is a small
predicate over one normalised telemetry record. The engine (``diagnosis.diagnose``) scores every
cause, requires an *anchor* signal plus corroboration from at least two independent telemetry
kinds, and abstains (``unknown``) when evidence is thin or two causes are indistinguishable.

Why not hardcode thresholds per cause?
* Names differ between stacks (``db_pool_utilization`` vs ``connection_pool_usage``), so signals match
  on normalised name patterns / aliases rather than exact strings.
* Units differ (ratio vs percent, ms vs s, bytes with a limit), so values are normalised first.
* A metric's own alert ``threshold`` (when the monitoring system supplies one) is preferred over our
  defaults, so the rules follow the *service's* SLOs where they are known.

The defaults below are heuristics, not universal SRE constants. They are version-stamped (``RULESET_VERSION``)
and evaluated by ``scripts/run_evaluation.py`` on a dev set and a separate held-out set.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

RULESET_VERSION = "2.0.0"
Record = dict[str, Any]


# --------------------------------------------------------------------------- helpers
def norm(text: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")


def num(value: Any) -> float | None:
    try:
        if value is None or isinstance(value, bool):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def as_ratio(rec: Record) -> float | None:
    """Normalise a utilisation-like metric to 0..1. Returns None when it cannot be done honestly
    (e.g. a raw byte count with no ``limit``), so such metrics never count as "saturated"."""
    value = num(rec.get("value"))
    if value is None:
        return None
    limit = num(rec.get("limit"))
    if limit:
        return value / limit
    unit = str(rec.get("unit", "")).lower()
    if unit in {"percent", "%", "pct"}:
        return value / 100.0
    if unit in {"ratio", "fraction"}:
        return value
    if unit:  # some other unit (bytes, count, ...) without a limit: not a ratio
        return None
    if value <= 1.5:
        return value
    return value / 100.0 if value <= 100 else None


def _ms_factor(unit: Any) -> float:
    unit = str(unit or "ms").lower()
    if unit in {"s", "sec", "secs", "second", "seconds"}:
        return 1000.0
    if unit in {"us", "µs", "microsecond", "microseconds"}:
        return 0.001
    return 1.0


def as_ms(rec: Record, field: str = "value") -> float | None:
    value = num(rec.get(field))
    return None if value is None else value * _ms_factor(rec.get("unit"))


def metric_breach(rec: Record, default_ms: float) -> bool:
    value = as_ms(rec)
    if value is None:
        return False
    threshold = as_ms(rec, "threshold")
    return value > (threshold if threshold else default_ms)


def name_matches(rec: Record, pattern: re.Pattern[str]) -> bool:
    return rec.get("kind") == "metric" and bool(pattern.search(norm(rec.get("name"))))


def log_matches(rec: Record, code: re.Pattern[str], message: re.Pattern[str]) -> bool:
    if rec.get("kind") != "log":
        return False
    return bool(code.search(str(rec.get("code", "")).upper()) or message.search(str(rec.get("message", ""))))


def span_ms(rec: Record) -> float:
    return num(rec.get("duration_ms")) or 0.0


def _re(pattern: str, flags: int = re.I) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# --------------------------------------------------------------------------- engine types
@dataclass(frozen=True)
class Signal:
    id: str
    kind: str  # metric | log | trace | deployment
    description: str
    weight: float
    match: Callable[[Record], bool]
    missing_hint: str  # what an operator should collect if this signal is absent


@dataclass(frozen=True)
class CauseRule:
    root_cause: str
    label: str
    anchors: tuple[str, ...]
    signals: tuple[Signal, ...]
    min_score: float = 0.6

    @property
    def total_weight(self) -> float:
        return sum(s.weight for s in self.signals)


# --------------------------------------------------------------------------- patterns
_POOL_METRIC = _re(r"pool.*(util|usage|used|in_use|active|saturat|checked_?out)|(util|usage|saturat).*pool")
_POOL_WAITING = _re(r"pool.*(waiting|queued|pending)")
_POOL_CODE = _re(r"POOL.*(TIMEOUT|EXHAUST|FULL)|(TIMEOUT|EXHAUST).*POOL|CONN(ECTION)?_?(ACQUIRE|CHECKOUT)|PGBOUNCER")
_POOL_MSG = _re(
    r"(acquire|obtain|borrow|check\s?out|getting|get)\b.{0,30}\bconnection"
    r"|\bpool\b.{0,40}(exhaust|full|timeout|timed out|no (idle|available))"
    r"|connection is not available|queuepool limit|pool limit.{0,20}reached|no more connections allowed|max_client_conn"
)
_POOL_SPAN = _re(r"acquire.*conn|get_?connection|pool.*(wait|acquire|checkout)|connection_?(acquire|checkout)|db_(session_)?connect")
_POOL_DEPLOY = _re(r"\bpool\b|max[_ ]?connections|connection limit")

_DEP_METRIC = _re(
    r"(supplier|dependency|upstream|downstream|external|partner|provider|vendor|third_party).*(p9\d|latency|duration|response)"
    r"|http_client.*(duration|latency|p9\d)|outbound.*(latency|duration)"
)
_DEP_ERR_METRIC = _re(r"(supplier|dependency|upstream|downstream|external|partner|provider|vendor).*(error|failure|fail)")
_DEP_CODE = _re(
    r"(SUPPLIER|DEPENDENCY|UPSTREAM|DOWNSTREAM|GATEWAY|PARTNER|VENDOR|EXTERNAL).*(TIMEOUT|TIMED_OUT|UNAVAILABLE|SLOW)|^(ETIMEDOUT|ESOCKETTIMEDOUT|ECONNABORTED)$"
)
_DEP_MSG = _re(
    r"(supplier|upstream|downstream|dependency|gateway|partner|vendor|external).{0,60}(time[ds]? ?out|did not respond|no response|exceeded)|\bconnect ETIMEDOUT\b"
)
_DEP_SPAN = _re(r"^(http|https|grpc|rpc|client)_|supplier|upstream|partner|vendor|https?://")

_SCHEMA_CODE = _re(r"SCHEMA|MIGRAT|UNDEFINED_COLUMN|NO_SUCH_COLUMN|UNKNOWN_COLUMN|COLUMN_MISSING|^PG_42703$|^42703$")
_SCHEMA_MSG = _re(
    r"(column|table|relation|field).{0,60}(does not exist|doesn.t exist|missing|not found|unknown|no such)"
    r"|no such (column|table)|undefined column|schema (mismatch|drift|out of date)"
    r"|migration.{0,30}(pending|not applied|missing)"
)
_SCHEMA_DEPLOY = _re(r"migrat|schema|\bcolumn\b|alter table|\bddl\b")
_WRITE_ERR_METRIC = _re(r"(db|database|write|insert).*(error|fail)")
_DB_SPAN = _re(r"^db_|^sql_|insert|update_|select|query")

_CACHE_HIT = _re(r"(cache|redis|memcached?|keyspace).*hit|hit_(rate|ratio)")
_DB_LOAD = _re(r"(db|database|postgres(ql)?|mysql|pg).*(qps|queries|query_rate|reads)|(qps|queries).*(db|database|postgres|mysql)")
_CACHE_CODE = _re(r"CACHE.*(MISS|STAMPEDE)|STAMPEDE|THUNDERING")
_CACHE_MSG = _re(r"cache.{0,30}(miss|stampede)|thundering herd|dogpile")

_MEM_METRIC = _re(r"memory.*(util|usage|used|rss|percent|working_set|resident|bytes)|(resident|working_set|rss).*memory|mem_(util|usage)")
_RESTART_METRIC = _re(r"restart")
_OOM_CODE = _re(r"OOM|OUT_?OF_?MEMORY|MEMORY_LIMIT")
_OOM_MSG = _re(r"\boom\b|out of memory|memory limit|killed.{0,30}memory|exceed\w*.{0,20}memory")
_HEAP_CODE = _re(r"HEAP|LEAK|^GC_")
_HEAP_MSG = _re(r"\bheap\b|retained|memory leak|garbage collect")


# --------------------------------------------------------------------------- signal predicates
def _pool_saturated(r: Record) -> bool:
    if name_matches(r, _POOL_WAITING):  # clients queued behind a full pool (e.g. pgbouncer cl_waiting)
        return (num(r.get("value")) or 0) > max(num(r.get("threshold")) or 0, 0)
    ratio = as_ratio(r) if name_matches(r, _POOL_METRIC) else None
    return ratio is not None and ratio >= 0.9


def _acquire_wait_span(r: Record) -> bool:
    if r.get("kind") != "trace":
        return False
    attrs = r.get("attributes") or {}
    waited = any("pool" in str(k).lower() and "wait" in str(k).lower() and (num(v) or 0) > 0 for k, v in attrs.items())
    named = bool(_POOL_SPAN.search(norm(r.get("operation"))))
    return (named or waited) and (span_ms(r) >= 250 or str(r.get("status", "")).upper() == "ERROR")


def _dep_latency(r: Record) -> bool:
    return name_matches(r, _DEP_METRIC) and metric_breach(r, 500.0)


def _slow_downstream_span(r: Record) -> bool:
    if r.get("kind") != "trace" or span_ms(r) < 1000:
        return False
    attrs = r.get("attributes") or {}
    op_raw = str(r.get("operation", "")).lower()
    if "peer.service" in attrs or "http.url" in attrs:
        return True
    if norm(op_raw).startswith(("db_", "cache_", "sql_")):
        return False
    return bool(_DEP_SPAN.search(norm(op_raw)) or _DEP_SPAN.search(op_raw))


def _ratio_over(r: Record, pattern: re.Pattern[str], default: float) -> bool:
    if not name_matches(r, pattern):
        return False
    value = num(r.get("value"))
    threshold = num(r.get("threshold"))
    return value is not None and value > (threshold if threshold else default)


def _low_hit_rate(r: Record) -> bool:
    ratio = as_ratio(r) if name_matches(r, _CACHE_HIT) else None
    return ratio is not None and ratio <= 0.35


def _db_load_elevated(r: Record) -> bool:
    if not name_matches(r, _DB_LOAD):
        return False
    value, threshold = num(r.get("value")), num(r.get("threshold"))
    if value is None:
        return False
    return value >= (1.5 * threshold if threshold else 1000.0)


def _slow_db_span(r: Record) -> bool:
    return (
        r.get("kind") == "trace" and span_ms(r) >= 1000 and bool(_DB_SPAN.search(norm(r.get("operation")))) and not _POOL_SPAN.search(norm(r.get("operation")))
    )


def _memory_high(r: Record) -> bool:
    ratio = as_ratio(r) if name_matches(r, _MEM_METRIC) else None
    return ratio is not None and ratio >= 0.9


def _restarts(r: Record) -> bool:
    return name_matches(r, _RESTART_METRIC) and (num(r.get("value")) or 0) > 0


# --------------------------------------------------------------------------- rule catalogue
RULES: tuple[CauseRule, ...] = (
    CauseRule(
        "database_connection_pool_exhaustion",
        "Database connection pool exhaustion",
        anchors=("pool_saturated", "pool_timeout_log"),
        signals=(
            Signal(
                "pool_saturated",
                "metric",
                "database pool utilization is at or above 90%",
                0.35,
                _pool_saturated,
                "database pool utilization / in-use connections",
            ),
            Signal(
                "pool_timeout_log",
                "log",
                "connection acquisition timeout is logged",
                0.25,
                lambda r: log_matches(r, _POOL_CODE, _POOL_MSG),
                "application logs around connection acquisition",
            ),
            Signal(
                "acquire_wait_trace",
                "trace",
                "trace shows time spent waiting for a database connection",
                0.25,
                _acquire_wait_span,
                "traces with connection-acquire spans",
            ),
            Signal(
                "pool_deployment",
                "deployment",
                "a recent deployment changed pool or connection settings",
                0.15,
                lambda r: r.get("kind") == "deployment" and bool(_POOL_DEPLOY.search(str(r.get("changes", "")))),
                "recent deployments touching pool configuration",
            ),
        ),
    ),
    CauseRule(
        "downstream_dependency_latency",
        "Downstream dependency latency",
        anchors=("dependency_latency", "dependency_timeout_log"),
        signals=(
            Signal(
                "dependency_latency",
                "metric",
                "downstream dependency latency exceeds its threshold",
                0.35,
                _dep_latency,
                "downstream dependency latency percentiles",
            ),
            Signal(
                "dependency_timeout_log",
                "log",
                "gateway or dependency timeout is logged",
                0.25,
                lambda r: log_matches(r, _DEP_CODE, _DEP_MSG),
                "client-side timeout logs for the dependency",
            ),
            Signal(
                "slow_downstream_span",
                "trace",
                "distributed trace identifies a slow downstream call",
                0.30,
                _slow_downstream_span,
                "traces for the slow downstream call",
            ),
            Signal(
                "dependency_error_rate",
                "metric",
                "dependency error rate is elevated",
                0.10,
                lambda r: _ratio_over(r, _DEP_ERR_METRIC, 0.05),
                "dependency error rate",
            ),
        ),
    ),
    CauseRule(
        "database_schema_mismatch",
        "Application/database schema mismatch",
        anchors=("schema_error_log",),
        signals=(
            Signal(
                "schema_error_log",
                "log",
                "application emitted an explicit schema mismatch error",
                0.50,
                lambda r: log_matches(r, _SCHEMA_CODE, _SCHEMA_MSG),
                "database error logs mentioning missing columns/tables",
            ),
            Signal(
                "schema_deployment",
                "deployment",
                "deployment notes indicate a schema or migration change",
                0.30,
                lambda r: r.get("kind") == "deployment" and bool(_SCHEMA_DEPLOY.search(str(r.get("changes", "")))),
                "recent deployments and the migration ledger",
            ),
            Signal(
                "write_error_metric",
                "metric",
                "database write error rate is elevated",
                0.10,
                lambda r: _ratio_over(r, _WRITE_ERR_METRIC, 0.05),
                "database write error rate",
            ),
            Signal(
                "failing_db_span",
                "trace",
                "a database span is failing quickly",
                0.10,
                lambda r: r.get("kind") == "trace" and str(r.get("status", "")).upper() == "ERROR" and bool(_DB_SPAN.search(norm(r.get("operation")))),
                "database spans from failing requests",
            ),
        ),
    ),
    CauseRule(
        "cache_stampede",
        "Cache stampede",
        anchors=("low_hit_rate", "cache_miss_log"),
        signals=(
            Signal("low_hit_rate", "metric", "cache hit rate is below 35%", 0.35, _low_hit_rate, "cache hit ratio"),
            Signal("db_load_elevated", "metric", "database query rate is elevated", 0.25, _db_load_elevated, "database query rate"),
            Signal("cache_miss_log", "log", "cache miss surge is logged", 0.25, lambda r: log_matches(r, _CACHE_CODE, _CACHE_MSG), "cache-layer logs"),
            Signal("slow_db_span", "trace", "slow database read spans on the hot path", 0.15, _slow_db_span, "traces of cache-miss fallbacks to the database"),
        ),
    ),
    CauseRule(
        "memory_pressure",
        "Application memory pressure",
        anchors=("memory_high", "oom_log"),
        signals=(
            Signal("memory_high", "metric", "memory utilization is at or above 90%", 0.35, _memory_high, "memory utilization against the container limit"),
            Signal("oom_log", "log", "worker OOM restart is logged", 0.30, lambda r: log_matches(r, _OOM_CODE, _OOM_MSG), "OOM-kill events from the runtime"),
            Signal("restarts", "metric", "container restart rate is non-zero", 0.20, _restarts, "container restart counts"),
            Signal(
                "heap_growth_log",
                "log",
                "heap growth or retained objects are logged",
                0.15,
                lambda r: log_matches(r, _HEAP_CODE, _HEAP_MSG),
                "heap/GC logs or a heap profile",
            ),
        ),
    ),
)

RULES_BY_CAUSE = {rule.root_cause: rule for rule in RULES}
