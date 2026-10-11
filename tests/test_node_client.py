"""
NodeClient is the only way any tool talks to Node (docs/VETRA_AI_ARCHITECTURE.md
§2, §6). Every call must carry the static service token AND the per-call
agent-context JWT — missing either would mean a tool call that /api/internal/ai/*
rejects outright, so this is worth locking down with its own test rather
than discovering it when a real tool first calls through.
"""
import httpx
import pytest

from app.core.config import Settings
from app.node_client.client import NodeClient


@pytest.fixture
def settings() -> Settings:
    return Settings(
        ai_service_token="svc-token",
        ai_service_jwt_public_key="unused-in-this-test",
        node_internal_url="http://node.internal",
    )


async def test_attaches_service_token_and_agent_context_headers(settings):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"ok": True})

    client = NodeClient(settings, transport=httpx.MockTransport(handler))
    res = await client.get("/api/internal/ai/ping", context_token="ctx-token")
    await client.aclose()

    assert res.status_code == 200
    assert captured["headers"]["x-service-token"] == "svc-token"
    assert captured["headers"]["x-agent-context"] == "ctx-token"
    assert captured["url"] == "http://node.internal/api/internal/ai/ping"


async def test_post_also_carries_both_headers(settings):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        return httpx.Response(201, json={"created": True})

    client = NodeClient(settings, transport=httpx.MockTransport(handler))
    res = await client.post("/api/internal/ai/whoami", context_token="ctx-token", json={"x": 1})
    await client.aclose()

    assert res.status_code == 201
    assert captured["headers"]["x-service-token"] == "svc-token"
    assert captured["headers"]["x-agent-context"] == "ctx-token"
