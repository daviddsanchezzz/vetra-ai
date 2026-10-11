"""
Verifies the agent-context JWT Node mints (docs/VETRA_AI_ARCHITECTURE.md §6).

PyJWT is Python's equivalent of Node's `jsonwebtoken`. Signed with RS256
(asymmetric): this service only ever holds the PUBLIC key (AI_SERVICE_JWT_PUBLIC_KEY),
never the private one, so it can verify a token but never mint one — even a
fully compromised ai-service process cannot forge a token Node would trust.
`algorithms=[ALGORITHM]` is passed explicitly so a token re-signed with
HS256 using the public key as if it were an HMAC secret is rejected outright
(the attack this RS256 switch exists to close).
"""
from enum import StrEnum

import jwt
from pydantic import BaseModel

ISSUER = "vetra-node"
AUDIENCE = "vetra-ai-service"
ALGORITHM = "RS256"


class AgentType(StrEnum):
    PUBLIC_BOOKING_AGENT = "PUBLIC_BOOKING_AGENT"
    BUSINESS_COPILOT = "BUSINESS_COPILOT"


# Pydantic model: validates shape AND that agentType is one of AgentType,
# not just "some string" — a value Node never issued fails here, not later.
class AgentContext(BaseModel):
    business_id: str
    agent_type: AgentType
    user_id: str | None = None


class InvalidAgentContext(Exception):
    """The token is missing, expired, wrongly signed, or for another audience/issuer."""


def verify_agent_context_token(token: str, public_key: str) -> AgentContext:
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
        )
    except jwt.PyJWTError as exc:
        raise InvalidAgentContext(str(exc)) from exc

    try:
        return AgentContext(
            business_id=payload["businessId"],
            agent_type=payload["agentType"],
            user_id=payload.get("userId"),
        )
    except (KeyError, ValueError) as exc:
        raise InvalidAgentContext(str(exc)) from exc
