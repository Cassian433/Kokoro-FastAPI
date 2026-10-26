import secrets
from unittest.mock import call, patch

import pytest
from fastapi.testclient import TestClient

from api.src.core.config import Settings, settings
from api.src.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def enable_auth(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", ["k1", "k2"])


def test_api_keys_json_env(monkeypatch):
    monkeypatch.setenv("API_KEYS", '["k1","k2"]')
    assert Settings(_env_file=None).api_keys == ["k1", "k2"]


def test_auth_disabled(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", [])
    response = client.get("/v1/models")
    assert response.status_code == 200
    assert response.json()["object"] == "list"


@pytest.mark.parametrize(
    "authorization",
    [None, "Bearer x", "Basic k2", "Bearer", "Bearer ", "Bearer k2 x", b"Bearer \xff"],
)
def test_auth_rejects_missing_or_invalid_token(authorization):
    headers = {} if authorization is None else {"Authorization": authorization}
    response = client.get("/v1/models", headers=headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json() == {
        "detail": {
            "error": "invalid_api_key",
            "message": "Missing or invalid API key",
            "type": "authentication_error",
        }
    }


@pytest.mark.parametrize("authorization", ["Bearer k1", "Bearer k2", "bearer k2"])
def test_auth_accepts_configured_keys(authorization):
    response = client.get("/v1/models", headers={"Authorization": authorization})
    assert response.status_code == 200
    assert response.json()["object"] == "list"


@pytest.mark.parametrize("token", ["k1", "longer-key", "wrong"])
def test_auth_compares_every_key_as_bytes(monkeypatch, token):
    keys = ["k1", "longer-key"]
    monkeypatch.setattr(settings, "api_keys", keys)
    with patch("secrets.compare_digest", wraps=secrets.compare_digest) as compare:
        response = client.get(
            "/v1/models", headers={"Authorization": f"Bearer {token}"}
        )
    assert response.status_code == (401 if token == "wrong" else 200)
    assert compare.call_args_list == [
        call(token.encode("utf-8"), key.encode("utf-8")) for key in keys
    ]


@pytest.mark.parametrize(
    "path", ["/v1/models", "/dev/model", "/dev/ssml", "/dev/tune", "/debug/threads"]
)
def test_auth_protects_api_routers(path):
    response = client.request("POST" if path == "/dev/tune" else "GET", path)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("path", ["/health", "/v1/test", "/web/config", "/web/"])
def test_auth_leaves_public_routes_open(path):
    response = client.get(path)
    assert response.status_code == 200


def test_openapi_bearer_security():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["components"]["securitySchemes"]["HTTPBearer"] == {
        "type": "http",
        "scheme": "bearer",
    }
    models = schema["paths"]["/v1/models"]["get"]
    assert models["security"] == [{"HTTPBearer": []}]
    assert not any(
        parameter["in"] == "header" and parameter["name"].lower() == "authorization"
        for parameter in models.get("parameters", [])
    )
    assert "422" not in models["responses"]
