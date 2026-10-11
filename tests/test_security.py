"""
Mirrors backend/test/unit/aiServiceAuth.test.js from the Node side: Python
only ever holds the PUBLIC key, so it must verify exactly what Node signs
and reject everything else, including the algorithm-confusion attack that
motivated switching to RS256 in the first place
(docs/VETRA_AI_ARCHITECTURE.md §6).
"""
import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.security import AgentType, InvalidAgentContext, verify_agent_context_token

ISSUER = "vetra-node"
AUDIENCE = "vetra-ai-service"


def _generate_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture(scope="module")
def keypair() -> tuple[str, str]:
    return _generate_keypair()


def _sign(private_key: str, **claims) -> str:
    now = int(time.time())
    payload = {"iat": now, "exp": now + 300, "iss": ISSUER, "aud": AUDIENCE, **claims}
    return jwt.encode(payload, private_key, algorithm="RS256")


def test_verifies_a_valid_token(keypair):
    private_key, public_key = keypair
    token = _sign(private_key, businessId="biz1", agentType="BUSINESS_COPILOT", userId="user1")

    ctx = verify_agent_context_token(token, public_key)

    assert ctx.business_id == "biz1"
    assert ctx.agent_type == AgentType.BUSINESS_COPILOT
    assert ctx.user_id == "user1"


def test_public_agent_has_no_user_id(keypair):
    private_key, public_key = keypair
    token = _sign(private_key, businessId="biz1", agentType="PUBLIC_BOOKING_AGENT", userId=None)

    ctx = verify_agent_context_token(token, public_key)

    assert ctx.agent_type == AgentType.PUBLIC_BOOKING_AGENT
    assert ctx.user_id is None


def test_rejects_a_token_forged_with_an_unrelated_keypair(keypair):
    _, public_key = keypair
    forged_private, _ = _generate_keypair()
    token = _sign(forged_private, businessId="biz1", agentType="BUSINESS_COPILOT", userId="attacker")

    with pytest.raises(InvalidAgentContext):
        verify_agent_context_token(token, public_key)


def _raw_hs256_token(secret: str, payload: dict) -> str:
    # Built by hand with hmac/base64, not jwt.encode(): PyJWT's own encode()
    # already refuses an asymmetric-looking key as an HMAC secret, which
    # would hide whether OUR verifier's `algorithms=[...]` pin actually
    # works, or we're just relying on PyJWT's encode-side guard. A real
    # attacker forging this wouldn't be going through PyJWT's encode either.
    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64url(signature)}"


def test_security_rejects_algorithm_confusion_hs256_with_public_key_as_secret(keypair):
    # If this ever accepted HS256 signed with the public key as the HMAC
    # secret, the public key (which ai-service holds, and which is not a
    # secret) would become forgeable — exactly what RS256 exists to prevent.
    _, public_key = keypair
    now = int(time.time())
    payload = {
        "iat": now, "exp": now + 300, "iss": ISSUER, "aud": AUDIENCE,
        "businessId": "biz1", "agentType": "BUSINESS_COPILOT", "userId": "attacker",
    }
    confused = _raw_hs256_token(public_key, payload)

    with pytest.raises(InvalidAgentContext):
        verify_agent_context_token(confused, public_key)


def test_rejects_wrong_audience(keypair):
    private_key, public_key = keypair
    now = int(time.time())
    payload = {
        "iat": now, "exp": now + 300, "iss": ISSUER, "aud": "some-other-service",
        "businessId": "biz1", "agentType": "BUSINESS_COPILOT", "userId": "u1",
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")

    with pytest.raises(InvalidAgentContext):
        verify_agent_context_token(token, public_key)


def test_rejects_wrong_issuer(keypair):
    private_key, public_key = keypair
    now = int(time.time())
    payload = {
        "iat": now, "exp": now + 300, "iss": "someone-else", "aud": AUDIENCE,
        "businessId": "biz1", "agentType": "BUSINESS_COPILOT", "userId": "u1",
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")

    with pytest.raises(InvalidAgentContext):
        verify_agent_context_token(token, public_key)


def test_rejects_an_expired_token(keypair):
    private_key, public_key = keypair
    now = int(time.time())
    payload = {
        "iat": now - 400, "exp": now - 100, "iss": ISSUER, "aud": AUDIENCE,
        "businessId": "biz1", "agentType": "BUSINESS_COPILOT", "userId": "u1",
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")

    with pytest.raises(InvalidAgentContext):
        verify_agent_context_token(token, public_key)


def test_rejects_an_unknown_agent_type(keypair):
    private_key, public_key = keypair
    token = _sign(private_key, businessId="biz1", agentType="SUPERADMIN_AGENT", userId="u1")

    with pytest.raises(InvalidAgentContext):
        verify_agent_context_token(token, public_key)
