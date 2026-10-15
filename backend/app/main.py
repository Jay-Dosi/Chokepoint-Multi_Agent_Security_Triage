"""CHOKEPOINT backend: FastAPI app, routers and lifespan."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .actions.outbox import outbox_dir
from .config import settings
from .db import ping
from .memory.embeddings import warm_up
from .orchestrator.mcp_client import client
from .routers import (
    actions,
    admin,
    cypher,
    evals,
    feedback,
    graph,
    health,
    investigations,
    mcp_tools,
    memory,
)
from .seed.loader import ensure_seeded

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
)
log = logging.getLogger("chokepoint")

_STARTUP_TASKS: set[asyncio.Task[None]] = set()

DESCRIPTION = (
    "Attack-path triage over a FalkorDB graph. Three agents coordinate through the graph, "
    "every tool call is an MCP call, and every risk number is computed in deterministic code."
)


async def _wait_for_database(attempts: int = 30, delay: float = 2.0) -> bool:
    for attempt in range(1, attempts + 1):
        if await asyncio.to_thread(ping):
            return True
        log.info("waiting for FalkorDB at %s:%s (%d/%d)", settings.falkordb_host, settings.falkordb_port, attempt, attempts)
        await asyncio.sleep(delay)
    return False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("CHOKEPOINT %s starting in '%s' agent mode", __version__, settings.effective_mode)
    if settings.mode_warning:
        log.warning(settings.mode_warning)
    try:
        outbox_dir()
    except OSError as exc:
        log.warning("outbox directory %s unavailable: %s", settings.outbox_dir, exc)

    if await _wait_for_database():
        try:
            stats = await asyncio.to_thread(ensure_seeded)
            log.info(
                "graph '%s' ready: %s nodes%s",
                settings.graph_name,
                stats.get("nodes"),
                " (seeded now)" if not stats.get("skipped") else "",
            )
        except Exception as exc:  # noqa: BLE001 - the API must still start
            log.exception("seeding failed: %s", exc)
    else:
        log.error("FalkorDB never became reachable; /api/health will report the problem")

    _track(asyncio.create_task(_connect_mcp()))
    if settings.embeddings_enabled:
        _track(asyncio.create_task(_warm_embeddings()))
    yield
    await client.close()
    log.info("CHOKEPOINT stopped")


def _track(task: asyncio.Task[None]) -> None:
    _STARTUP_TASKS.add(task)
    task.add_done_callback(_STARTUP_TASKS.discard)


async def _warm_embeddings() -> None:
    status = await asyncio.to_thread(warm_up)
    log.info("embeddings: %s", status)


async def _connect_mcp() -> None:
    for attempt in range(1, 16):
        if await client.connect():
            tools = await client.list_tools(refresh=True)
            log.info("discovered %d MCP tools from %s", len(tools), settings.mcp_url)
            return
        await asyncio.sleep(2.0 * attempt if attempt < 5 else 10.0)
    log.error("could not reach the MCP server at %s: %s", settings.mcp_url, client.last_error)


app = FastAPI(
    title="CHOKEPOINT",
    version=__version__,
    description=DESCRIPTION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list or ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

for module in (
    health,
    graph,
    cypher,
    investigations,
    feedback,
    actions,
    memory,
    evals,
    mcp_tools,
    admin,
):
    app.include_router(module.router, prefix="/api")


@app.get("/api", include_in_schema=False)
async def api_root() -> dict[str, str]:
    return {
        "name": "CHOKEPOINT",
        "version": __version__,
        "agent_mode": settings.effective_mode,
        "graph": settings.graph_name,
        "docs": "/docs",
    }
