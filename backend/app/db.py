"""FalkorDB access layer.

Every Cypher statement in the system goes through :func:`ro_query` or
:func:`rw_query` so that timing, parameterisation and error handling are
uniform. The three functions marked WRAPPER below are the only places that
touch the ``falkordb`` client surface directly; if a client API changes, they
are the only things to fix.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from falkordb import FalkorDB

from .config import settings

log = logging.getLogger("chokepoint.db")

_lock = threading.Lock()
_client: FalkorDB | None = None


@dataclass(slots=True)
class QueryOutcome:
    """Normalised query result: plain Python scalars, lists and dicts only."""

    cypher: str
    header: list[str]
    rows: list[list[Any]]
    latency_ms: float
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.header, row, strict=False)) for row in self.rows]

    def first(self) -> dict[str, Any] | None:
        rows = self.dicts()
        return rows[0] if rows else None

    def column(self, name: str) -> list[Any]:
        if name not in self.header:
            return []
        idx = self.header.index(name)
        return [row[idx] for row in self.rows]

    def scalar(self, default: Any = None) -> Any:
        if not self.rows or not self.rows[0]:
            return default
        return self.rows[0][0]


# --- WRAPPER 1: client construction -----------------------------------------
def client() -> FalkorDB:
    global _client
    with _lock:
        if _client is None:
            _client = FalkorDB(host=settings.falkordb_host, port=settings.falkordb_port)
        return _client


def graph_handle(name: str | None = None) -> Any:
    return client().select_graph(name or settings.graph_name)


def _header_names(result: Any) -> list[str]:
    raw = getattr(result, "header", None) or []
    names: list[str] = []
    for item in raw:
        if isinstance(item, (list, tuple)):
            value = item[-1]
        else:
            value = item
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        names.append(str(value))
    return names


def _plain(value: Any) -> Any:
    """Convert client objects (Node/Edge/Path) into plain structures."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    props = getattr(value, "properties", None)
    if isinstance(props, dict):
        out = {str(k): _plain(v) for k, v in props.items()}
        labels = getattr(value, "labels", None)
        if labels:
            out["__labels"] = [str(label) for label in labels]
        relation = getattr(value, "relation", None)
        if relation:
            out["__type"] = str(relation)
        return out
    return str(value)


# --- WRAPPER 2: read-only query ---------------------------------------------
def ro_query(
    cypher: str,
    params: dict[str, Any] | None = None,
    *,
    graph: str | None = None,
    timeout_ms: int | None = None,
) -> QueryOutcome:
    handle = graph_handle(graph)
    kwargs: dict[str, Any] = {}
    if timeout_ms is not None:
        kwargs["timeout"] = timeout_ms
    started = time.perf_counter()
    try:
        result = handle.ro_query(cypher, params or {}, **kwargs)
    except AttributeError:
        result = handle.query(cypher, params or {}, **kwargs)
    latency = (time.perf_counter() - started) * 1000.0
    return QueryOutcome(
        cypher=cypher.strip(),
        header=_header_names(result),
        rows=[[_plain(cell) for cell in row] for row in (result.result_set or [])],
        latency_ms=round(latency, 2),
        params=dict(params or {}),
    )


# --- WRAPPER 3: write query -------------------------------------------------
def rw_query(
    cypher: str,
    params: dict[str, Any] | None = None,
    *,
    graph: str | None = None,
) -> QueryOutcome:
    handle = graph_handle(graph)
    started = time.perf_counter()
    result = handle.query(cypher, params or {})
    latency = (time.perf_counter() - started) * 1000.0
    return QueryOutcome(
        cypher=cypher.strip(),
        header=_header_names(result),
        rows=[[_plain(cell) for cell in row] for row in (result.result_set or [])],
        latency_ms=round(latency, 2),
        params=dict(params or {}),
    )


def try_query(cypher: str, params: dict[str, Any] | None = None, *, graph: str | None = None) -> str:
    """Run a statement that is allowed to fail (index creation, optional procedures)."""
    try:
        rw_query(cypher, params, graph=graph)
        return "ok"
    except Exception as exc:  # noqa: BLE001 - FalkorDB raises bare exceptions for DDL conflicts
        message = str(exc).strip() or exc.__class__.__name__
        log.debug("statement skipped: %s -> %s", cypher.strip().splitlines()[0], message)
        return message


def _raw_connection() -> Any:
    return getattr(client(), "connection", None)


def copy_graph(source: str, destination: str) -> None:
    """GRAPH.COPY source -> destination."""
    handle = graph_handle(source)
    try:
        handle.copy(destination)
        return
    except AttributeError:
        pass
    connection = _raw_connection()
    if connection is None:
        raise RuntimeError("this falkordb client exposes neither Graph.copy nor a raw connection")
    connection.execute_command("GRAPH.COPY", source, destination)


def delete_graph(name: str) -> None:
    try:
        graph_handle(name).delete()
    except Exception as exc:  # noqa: BLE001 - deleting a missing scratch graph is not an error
        log.debug("graph delete skipped for %s: %s", name, exc)


def ping() -> bool:
    """True when the server answers. Falls back to a trivial query."""
    try:
        connection = _raw_connection()
        if connection is not None:
            return bool(connection.ping())
    except Exception:  # noqa: BLE001 - fall through to the query probe
        pass
    try:
        return int(ro_query("RETURN 1 AS ok").scalar(0) or 0) == 1
    except Exception:  # noqa: BLE001
        return False


def graph_is_empty(graph: str | None = None) -> bool:
    try:
        outcome = ro_query("MATCH (n) RETURN count(n) AS c", graph=graph)
    except Exception:  # noqa: BLE001
        return True
    return int(outcome.scalar(0) or 0) == 0


def node_count(graph: str | None = None) -> int:
    try:
        return int(ro_query("MATCH (n) RETURN count(n) AS c", graph=graph).scalar(0) or 0)
    except Exception:  # noqa: BLE001
        return 0
