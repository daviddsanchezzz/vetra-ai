"""
FastAPI's TestClient drives the real app in-process — the Python
equivalent of Node's supertest(app). Verifies the full chain: /health is
open, /v1/ping needs both the service token and a valid agent-context JWT
(mirrors backend/test/unit/aiInternalRouter.test.js).
"""
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.main import app

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


@pytest.fixture
def client(keypair):
    _, public_key = keypair
    test_settings = Settings(ai_service_token="test-service-token", ai_service_jwt_public_key=public_key)
    app.dependency_overrides[get_settings] = lambda: test_settings
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _mint(private_key: str, **claims) -> str:
    now = int(time.time())
    payload = {"iat": now, "exp": now + 300, "iss": ISSUER, "aud": AUDIENCE, **claims}
    return jwt.encode(payload, private_key, algorithm="RS256")


def test_health_is_public(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_ping_rejects_without_a_service_token(client, keypair):
    private_key, _ = keypair
    token = _mint(private_key, businessId="biz1", agentType="PUBLIC_BOOKING_AGENT", userId=None)

    res = client.get("/v1/ping", headers={"X-Agent-Context": token})

    assert res.status_code == 401


def test_ping_rejects_without_an_agent_context(client):
    res = client.get("/v1/ping", headers={"X-Service-Token": "test-service-token"})
    assert res.status_code == 401


def test_ping_rejects_a_wrong_service_token(client, keypair):
    private_key, _ = keypair
    token = _mint(private_key, businessId="biz1", agentType="PUBLIC_BOOKING_AGENT", userId=None)

    res = client.get("/v1/ping", headers={"X-Service-Token": "guessed", "X-Agent-Context": token})

    assert res.status_code == 401


def test_ping_works_end_to_end_for_the_public_agent(client, keypair):
    private_key, _ = keypair
    token = _mint(private_key, businessId="biz1", agentType="PUBLIC_BOOKING_AGENT", userId=None)

    res = client.get("/v1/ping", headers={"X-Service-Token": "test-service-token", "X-Agent-Context": token})

    assert res.status_code == 200
    assert res.json() == {"businessId": "biz1", "agentType": "PUBLIC_BOOKING_AGENT", "userId": None}


def test_ping_works_end_to_end_for_the_business_copilot(client, keypair):
    private_key, _ = keypair
    token = _mint(private_key, businessId="biz1", agentType="BUSINESS_COPILOT", userId="user1")

    res = client.get("/v1/ping", headers={"X-Service-Token": "test-service-token", "X-Agent-Context": token})

    assert res.status_code == 200
    assert res.json() == {"businessId": "biz1", "agentType": "BUSINESS_COPILOT", "userId": "user1"}
