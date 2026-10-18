"""Offline functional tests. They generate a temporary RSA key pair for testing only."""
import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
import main


def test_four_grading_cases(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    monkeypatch.setattr(main, "PUBLIC_KEY", public_pem)
    client = TestClient(main.app)

    def mint(*, expiry=120, audience=main.AUDIENCE, issuer=main.ISSUER):
        return jwt.encode({
            "iss": issuer,
            "aud": audience,
            "exp": int(time.time()) + expiry,
            "email": "student@example.com",
            "sub": "student-123",
        }, key, algorithm="RS256")

    ok = client.post("/verify", json={"token": mint()})
    assert ok.status_code == 200
    assert ok.json() == {
        "valid": True,
        "email": "student@example.com",
        "sub": "student-123",
        "aud": main.AUDIENCE,
    }

    for bad in [mint(expiry=-120), mint(audience="wrong-audience"),
                mint(issuer="https://wrong-issuer")]:
        result = client.post("/verify", json={"token": bad})
        assert result.status_code == 401
        assert result.json() == {"valid": False}

    good = mint()
    head, payload, signature = good.split(".")
    # Modify signed payload without signing again.
    import base64, json
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    decoded["sub"] = "tampered"
    modified = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode().rstrip("=")
    tampered = ".".join([head, modified, signature])
    result = client.post("/verify", json={"token": tampered})
    assert result.status_code == 401
    assert result.json() == {"valid": False}

    malformed = client.post("/verify", json={"token": "garbage"})
    assert malformed.status_code == 401
    assert malformed.json() == {"valid": False}
    invalid_json = client.post("/verify", content="not json", headers={"Content-Type": "application/json"})
    assert invalid_json.status_code == 401
    assert invalid_json.json() == {"valid": False}
