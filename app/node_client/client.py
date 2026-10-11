"""
The only way a tool talks to Node (docs/VETRA_AI_ARCHITECTURE.md §2, §6).
Every call carries the static X-Service-Token (set once, at construction)
and the per-call X-Agent-Context JWT (differs per conversation) — missing
either is exactly what /api/internal/ai/* on the Node side rejects.
"""
import httpx

from app.core.config import Settings


class NodeClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self._client = httpx.AsyncClient(
            base_url=settings.node_internal_url,
            headers={"X-Service-Token": settings.ai_service_token},
            timeout=10.0,
            transport=transport,
        )

    async def get(self, path: str, *, context_token: str, **kwargs) -> httpx.Response:
        return await self._client.get(path, headers={"X-Agent-Context": context_token}, **kwargs)

    async def post(self, path: str, *, context_token: str, **kwargs) -> httpx.Response:
        return await self._client.post(path, headers={"X-Agent-Context": context_token}, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()
