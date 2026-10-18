# IITM TDS FastAPI RS256 JWT verifier

The `POST /verify` endpoint accepts `{"token":"..."}`.

- Valid RS256 signature, issuer `https://idp.exam.local`, exact audience `tds-u7rclj06.apps.exam.local`, and non-expired `exp`: HTTP 200, `{"valid":true,"email":...,"sub":...,"aud":...}`.
- Invalid JWT, bad signature, wrong issuer/audience, expired/missing expiry, or malformed input: HTTP 401, `{"valid":false}`.

The embedded key is a **public** verification key. No private signing key is required.

## Local Windows PowerShell

```
cd D:\TDS\jwt-verify-fastapi
py -m pip install -r requirements.txt
py -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs` and try `POST /verify` with an invalid token to confirm HTTP 401. All grader cases require valid test JWTs signed by the matching IdP private key; do not attempt to sign tokens with this public key.

## Deploy using GitHub + Render (no Git Bash)

1. Create a new **public or private** GitHub repository while signed into your account.
2. In Chrome, choose `Add file -> Upload files`, upload `main.py`, `requirements.txt`, `render.yaml`, and commit.
3. Open Render (https://dashboard.render.com/), select `New -> Web Service`, connect the GitHub repository and confirm the runtime is Python.
4. Build command: `pip install -r requirements.txt`
5. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Select an **always-on** instance if the grader uses short timeouts: sleeping services can take too long to wake.
7. After deployment, use `https://<your-service>.onrender.com/verify` as the submission URL.

Do not use GitHub Pages for FastAPI; GitHub Pages supports static sites only. Do not submit an example URL before the actual service is live.
