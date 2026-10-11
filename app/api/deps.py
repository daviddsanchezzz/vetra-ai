"""
FastAPI dependencies (`Depends(...)`): a route declares what it needs and
FastAPI calls these functions to produce it, raising before the route body
ever runs if one fails. The Python analogue of Express middleware, but
composed per-route instead of mounted on a router.
"""
import hmac

from fastapi import Depends, Header, HTTPException, status

from app.core.config import Settings, get_settings
from app.core.security import AgentContext, InvalidAgentContext, verify_agent_context_token


def require_service_token(
    x_service_token: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    if not x_service_token or not hmac.compare_digest(x_service_token, settings.ai_service_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token de servicio invalido")


def require_agent_context(
    x_agent_context: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
    _service: None = Depends(require_service_token),
) -> AgentContext:
    if not x_agent_context:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Falta el contexto del agente")
    try:
        return verify_agent_context_token(x_agent_context, settings.ai_service_jwt_public_key)
    except InvalidAgentContext as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Contexto del agente invalido") from exc
