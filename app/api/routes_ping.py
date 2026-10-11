"""
Proves the Node<->ai-service auth chain end-to-end before any real agent
tool exists — mirrors backend/core/routes/aiInternal.js's /ping.
"""
from fastapi import APIRouter, Depends

from app.api.deps import require_agent_context
from app.core.security import AgentContext

router = APIRouter(prefix="/v1")


@router.get("/ping")
def ping(ctx: AgentContext = Depends(require_agent_context)) -> dict:
    return {"businessId": ctx.business_id, "agentType": ctx.agent_type.value, "userId": ctx.user_id}
