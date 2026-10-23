"""API endpoint tests for the FastAPI application using TestClient."""

from __future__ import annotations

from fastapi import status
from fastapi.testclient import TestClient


def test_activate_without_client_build(client: TestClient) -> None:
    """POST /v1/keyauth/activate without client_build returns 422 validation error."""
    response = client.post(
        "/v1/keyauth/activate",
        json={
            "key": "ABCD-EFGH-JKLM-NPQR",
            "hwid": "test-hwid-value-1234567890ab",
        },
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_activate_with_client_build_not_configured(client: TestClient) -> None:
    """POST /v1/keyauth/activate with client_build returns 200 with success=False.

    KeyAuth credentials are present in test settings but the live KeyAuth API
    rejects the test values, so validation fails and the endpoint returns
    success=False within a 200 envelope.
    """
    response = client.post(
        "/v1/keyauth/activate",
        json={
            "key": "ABCD-EFGH-JKLM-NPQR",
            "hwid": "test-hwid-value-1234567890ab",
            "client_build": "1.0.0",
        },
    )
    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["data"]["success"] is False


def test_integrity_challenge_requires_auth(client: TestClient) -> None:
    """GET /v1/integrity/challenge without token returns 401."""
    response = client.get("/v1/integrity/challenge")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_integrity_check_requires_auth(client: TestClient) -> None:
    """POST /v1/integrity/check without token returns 401."""
    response = client.post(
        "/v1/integrity/check",
        json={
            "nonce": "0123456789abcdef",
            "client_build": "1.0.0",
            "generated_at": "2024-01-01T00:00:00Z",
            "files": [],
            "signature": "01234567890123456789012345678901",
        },
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_integrity_challenge_returns_nonce(client: TestClient, auth_token: tuple[str, int]) -> None:
    """Authenticated GET /v1/integrity/challenge returns a nonce."""
    token = auth_token[0]
    response = client.get(
        "/v1/integrity/challenge",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()["data"]
    assert data["nonce"]


def test_security_event_requires_auth(client: TestClient) -> None:
    """POST /v1/security/event without token returns 401."""
    response = client.post(
        "/v1/security/event",
        json={
            "level": 1,
            "category": "MANIFEST",
            "rule": "TEST_RULE",
            "reason": "test security event",
        },
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_security_status_requires_auth(client: TestClient) -> None:
    """GET /v1/security/status without token returns 401."""
    response = client.get("/v1/security/status")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_security_event_with_auth(client: TestClient, auth_token: tuple[str, int]) -> None:
    """Authenticated POST /v1/security/event returns event_id."""
    token = auth_token[0]
    response = client.post(
        "/v1/security/event",
        json={
            "level": 1,
            "category": "MANIFEST",
            "rule": "TEST_RULE",
            "reason": "test security event",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()["data"]
    assert data["event_id"]
