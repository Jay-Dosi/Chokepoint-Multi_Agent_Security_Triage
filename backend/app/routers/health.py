"""GET /api/health - database, MCP, algorithms, embeddings and agent mode."""

from __future__ import annotations

from fastapi import APIRouter

from app.config import settings
from app.db import node_count, ping
from app.memory.embeddings import embedder
from app.models import CapabilityReport, EmbeddingStatus, HealthResponse
from app.orchestrator.mcp_client import client
from mcp_server import algos

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    falkordb = ping()
    tools = await client.list_tools(refresh=True) if falkordb else []
    try:
        capabilities = CapabilityReport(**algos.capability_report()) if falkordb else CapabilityReport()
    except Exception:  # noqa: BLE001 - capability probing is advisory
        capabilities = CapabilityReport()
    return HealthResponse(
        ok=falkordb and bool(tools),
        falkordb=falkordb,
        graph=settings.graph_name,
        node_count=node_count() if falkordb else 0,
        mcp=bool(tools),
        mcp_url=settings.mcp_url,
        mcp_tools=len(tools),
        agent_mode=settings.effective_mode,
        configured_agent_mode=settings.agent_mode,
        model=settings.anthropic_model if settings.effective_mode == "live" else "scripted",
        mode_warning=settings.mode_warning or (client.last_error if not tools else ""),
        embeddings=EmbeddingStatus(**embedder().status()),
        capabilities=capabilities,
        seed_scale=settings.seed_scale,
        outbox_dir=settings.outbox_dir,
    )
