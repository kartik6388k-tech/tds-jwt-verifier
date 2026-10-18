"""IITM TDS JWT verification endpoint — only public verification material is used."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import jwt
from jwt.exceptions import InvalidTokenError

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-u7rclj06.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI(title="TDS JWT Verifier")


@app.get("/")
def health():
    return {"status": "ready", "verify_endpoint": "/verify"}


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("Expected JSON object")
        token = body.get("token")
        if not isinstance(token, str) or not token or len(token) > 10000:
            raise ValueError("Invalid token")

        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["iss", "aud", "exp"]},
            leeway=0,
        )
        # Ensure the audience claim is exactly the assigned string.
        if claims.get("aud") != AUDIENCE:
            raise ValueError("Wrong audience")

        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims["aud"],
        }
    except (InvalidTokenError, ValueError, TypeError, UnicodeError):
        return JSONResponse(status_code=401, content={"valid": False})
