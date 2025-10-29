# Kerliix OAuth Backend (FastAPI) - Local Dev

## Prereqs
- Python 3.10+
- The Python SDK package `kerliix_oauth` must be installed locally (pip install -e . from the SDK directory) or available on PYTHONPATH.

## Setup
1. Copy `.env.sample` to `.env` and fill in `KERLIIX_CLIENT_ID`, etc.
2. Create a Python virtualenv and install dependencies:
 ```
python -m venv .venv
source .venv/bin/activate # macOS / Linux
.venv\Scripts\activate # Windows
pip install -r requirements.txt
```

3. Ensure `kerliix_oauth` SDK package is installed or importable:
- From the SDK folder: `pip install -e .`

## Run
Start the backend on port 5175:
```
uvicorn main:app --host 0.0.0.0 --port 5175 --reload
```


## Flow
- Visit `http://localhost:5175/login` to begin the OAuth flow (you will be redirected to Kerliix auth)
- After authenticating, Kerliix will redirect back to `http://localhost:5175/callback` which exchanges the code
- Frontend (expected at `http://localhost:5176`) can then call `/me` and `/tokens` etc. Cookies are used to track session.

## Notes
- This example uses an **in-memory** session and PKCE store — good for local testing only.
- For production:
  - Use a persistent DB or redis for sessions.
  - Use secure cookies (HttpOnly, Secure)
  - Use HTTPS for all endpoints.

## Quick explanation of choices & security notes
- FastAPI: modern ASGI framework, easy to run with uvicorn.

PKCE: implemented by calling the Python SDK's get_auth_url with usePKCE=True; backend stores the code_verifier keyed by state.

Session management: we use a signed cookie session_id and an in-memory SESSION_STORE. This is only for development. For production use server-side session storage (Redis, DB).

CORS: configured to allow frontend at http://localhost:5176.

Revocation: /revoke calls the SDK revoke endpoint and clears session.