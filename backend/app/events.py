"""Event bus for the SSE stream, with graph persistence and replay.

Events are fanned out to live subscribers and written to the graph as an
`(:Investigation)-[:HAS_EVENT]->(:Event)` chain, so a finished investigation
can be replayed from the graph alone.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from .db import ro_query, rw_query
from .models import StreamEvent

log = logging.getLogger("chokepoint.events")

CREATE_EVENT_CYPHER = """
MATCH (i:Investigation {id: $iid})
CREATE (e:Event {id: $eid, n: $n, type: $type, ts: $ts, payload_json: $payload})
CREATE (i)-[:HAS_EVENT]->(e)
RETURN e.id AS id
"""

READ_EVENTS_CYPHER = """
MATCH (:Investigation {id: $iid})-[:HAS_EVENT]->(e:Event)
RETURN e.n AS n, e.type AS type, e.ts AS ts, e.payload_json AS payload_json
ORDER BY e.n
LIMIT 2000
"""

QUEUE_LIMIT = 2000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventBus:
    """One bus for the whole process: investigations are keyed by id."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[StreamEvent]]] = {}
        self._buffer: dict[str, list[StreamEvent]] = {}
        self._sequence: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def emit(self, investigation_id: str, event_type: str, payload: dict[str, Any]) -> StreamEvent:
        async with self._lock:
            seq = self._sequence.get(investigation_id, 0) + 1
            self._sequence[investigation_id] = seq
        event = StreamEvent(
            type=event_type,  # type: ignore[arg-type]  validated by the EventType literal
            ts=now_iso(),
            investigation_id=investigation_id,
            seq=seq,
            payload=payload,
        )
        self._buffer.setdefault(investigation_id, []).append(event)
        for queue in list(self._subscribers.get(investigation_id, [])):
            if queue.qsize() < QUEUE_LIMIT:
                queue.put_nowait(event)
        await asyncio.to_thread(self._persist, event)
        return event

    def _persist(self, event: StreamEvent) -> None:
        try:
            rw_query(
                CREATE_EVENT_CYPHER,
                {
                    "iid": event.investigation_id,
                    "eid": f"{event.investigation_id}-E{event.seq}",
                    "n": event.seq,
                    "type": event.type,
                    "ts": event.ts,
                    "payload": json.dumps(event.payload, default=str)[:60000],
                },
            )
        except Exception as exc:  # noqa: BLE001 - a dropped event must not break a run
            log.warning("could not persist event %s/%s: %s", event.investigation_id, event.seq, exc)

    def subscribe(self, investigation_id: str) -> asyncio.Queue[StreamEvent]:
        queue: asyncio.Queue[StreamEvent] = asyncio.Queue()
        self._subscribers.setdefault(investigation_id, []).append(queue)
        return queue

    def unsubscribe(self, investigation_id: str, queue: asyncio.Queue[StreamEvent]) -> None:
        queues = self._subscribers.get(investigation_id)
        if not queues:
            return
        if queue in queues:
            queues.remove(queue)
        if not queues:
            self._subscribers.pop(investigation_id, None)

    async def history(self, investigation_id: str) -> list[StreamEvent]:
        """Buffered events for a live run, otherwise the persisted chain."""
        buffered = self._buffer.get(investigation_id)
        if buffered:
            return list(buffered)
        rows = await asyncio.to_thread(self._read_persisted, investigation_id)
        return rows

    def _read_persisted(self, investigation_id: str) -> list[StreamEvent]:
        try:
            outcome = ro_query(READ_EVENTS_CYPHER, {"iid": investigation_id})
        except Exception as exc:  # noqa: BLE001
            log.warning("could not read events for %s: %s", investigation_id, exc)
            return []
        events: list[StreamEvent] = []
        for row in outcome.dicts():
            try:
                payload = json.loads(str(row.get("payload_json") or "{}"))
            except json.JSONDecodeError:
                payload = {}
            events.append(
                StreamEvent(
                    type=str(row.get("type") or "agent_message"),  # type: ignore[arg-type]
                    ts=str(row.get("ts") or ""),
                    investigation_id=investigation_id,
                    seq=int(row.get("n") or 0),
                    payload=payload,
                )
            )
        return events

    def forget(self, investigation_id: str) -> None:
        self._buffer.pop(investigation_id, None)

    def live_count(self) -> int:
        return sum(len(v) for v in self._subscribers.values())


bus = EventBus()


def sse_frame(event: StreamEvent) -> str:
    return f"event: {event.type}\ndata: {event.model_dump_json()}\n\n"


async def event_stream(investigation_id: str, *, is_finished: bool) -> AsyncIterator[str]:
    """Replay then follow. Subscribing first means nothing is missed in between."""
    queue = bus.subscribe(investigation_id)
    seen: set[int] = set()
    try:
        replayed_types: set[str] = set()
        for event in await bus.history(investigation_id):
            seen.add(event.seq)
            replayed_types.add(event.type)
            yield sse_frame(event)
        if is_finished and "run_finished" in replayed_types:
            return
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15.0)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                continue
            if event.seq in seen:
                continue
            seen.add(event.seq)
            yield sse_frame(event)
            if event.type == "run_finished":
                return
    finally:
        bus.unsubscribe(investigation_id, queue)
