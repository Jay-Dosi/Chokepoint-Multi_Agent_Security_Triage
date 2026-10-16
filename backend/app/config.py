"""Environment-backed settings shared by the API and the MCP server."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """All runtime configuration. Names map to upper-case environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash-lite"
    agent_mode: str = "live"

    falkordb_host: str = "localhost"
    falkordb_port: int = 6379
    graph_name: str = "chokepoint"

    mcp_url: str = "http://localhost:8765/mcp"
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8765

    embeddings: str = "fastembed"
    embedding_model: str = "BAAI/bge-small-en-v1.5"

    seed_scale: int = 1
    outbox_dir: str = "/data/outbox"
    ground_truth_path: str = ""

    slack_webhook_url: str = ""
    github_token: str = ""
    github_repo: str = ""

    cors_origins: str = "http://localhost:8080,http://localhost:5173,http://127.0.0.1:8080"

    scout_max_tool_calls: int = 14
    skeptic_max_tool_calls: int = 10
    scribe_max_tool_calls: int = 8
    agent_timeout_s: float = 180.0
    llm_max_tokens: int = 2600
    llm_temperature: float = 0.2

    path_max_hops: int = 7
    path_candidate_limit: int = 4000
    tool_payload_budget_bytes: int = 6144
    cypher_row_cap: int = 200
    cypher_timeout_ms: int = 5000

    sim_graph_prefix: str = Field(default="sim_", description="Prefix for scratch counterfactual graphs.")

    @property
    def effective_mode(self) -> str:
        """`live` only when a key is actually present, otherwise `scripted`."""
        if self.agent_mode.strip().lower() == "scripted":
            return "scripted"
        return "live" if self.gemini_api_key.strip() else "scripted"

    @property
    def mode_warning(self) -> str:
        if self.agent_mode.strip().lower() == "live" and not self.gemini_api_key.strip():
            return "GEMINI_API_KEY is empty; falling back to scripted agents."
        return ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ground_truth_file(self) -> Path:
        if self.ground_truth_path.strip():
            return Path(self.ground_truth_path.strip())
        return PACKAGE_ROOT / "seed" / "ground_truth.json"

    @property
    def outbox_path(self) -> Path:
        return Path(self.outbox_dir)

    @property
    def embeddings_enabled(self) -> bool:
        return self.embeddings.strip().lower() == "fastembed"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
