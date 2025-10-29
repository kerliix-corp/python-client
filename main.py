# main.py
import os
import secrets
from typing import Optional, Dict
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

# Load .env (optional)
load_dotenv()

# Import the Python SDK you created earlier.
# Make sure your package is importable (e.g. pip install -e . or add to PYTHONPATH)
from kerliix_oauth import KerliixOAuth, OAuthError

# Configuration (via environment variables or defaults)
config = Config(".env")
CLIENT_ID = os.getenv("KERLIIX_CLIENT_ID") or config("KERLIIX_CLIENT_ID", default=None)
CLIENT_SECRET = os.getenv("KERLIIX_CLIENT_SECRET") or config("KERLIIX_CLIENT_SECRET", default=None)
REDIRECT_URI = os.getenv("KERLIIX_REDIRECT_URI") or config("KERLIIX_REDIRECT_URI", default="http://localhost:5175/callback")
BASE_URL = os.getenv("KERLIIX_BASE_URL") or config("KERLIIX_BASE_URL", default="https://api.kerliix.com")
SESSION_SECRET = os.getenv("SESSION_SECRET") or config("SESSION_SECRET", default=secrets.token_urlsafe(32))

if not CLIENT_ID:
    raise RuntimeError("KERLIIX_CLIENT_ID must be set in environment")

# FastAPI app
app = FastAPI(title="Kerliix OAuth Backend (Dev)")

# Allow CORS from the frontend origin (http://localhost:5176)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5176"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Add simple session middleware (signed cookie). For production use a secure store.
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# In-memory stores for demo purposes
# session_store: session_id -> {"token": TokenResponse dataclass (as dict), "created_at": int, ...}
SESSION_STORE: Dict[str, dict] = {}

# PKCE/state store: ephemeral mapping state -> code_verifier
PKCE_STORE: Dict[str, str] = {}

# Instantiate KerliixOAuth client
kerliix_client = KerliixOAuth(
    client_id=CLIENT_ID,
    redirect_uri=REDIRECT_URI,
    base_url=BASE_URL,
    client_secret=CLIENT_SECRET,  # optional if you want PKCE-only flows
)


def _get_session_id(request: Request) -> Optional[str]:
    # Using cookie named "session_id" to track the user session
    return request.cookies.get("session_id")


def _set_session_cookie(response: Response, session_id: str):
    # Set cookie for the frontend, cookie is HttpOnly=false so frontend may read for debugging if needed.
    # In production make HttpOnly=True and secure=True (HTTPS).
    response.set_cookie("session_id", session_id, httponly=True, secure=False, samesite="lax")


@app.get("/")
async def root():
    return {"message": "Kerliix OAuth backend running on localhost:5175"}


@app.get("/login")
async def login(response: Response, scopes: Optional[str] = None):
    """
    Start OAuth login flow.
    - scopes: optional space-separated list (e.g. "openid profile email")
    Returns a RedirectResponse to the Kerliix authorize URL.
    """
    # generate a random state for CSRF protection
    state = secrets.token_urlsafe(16)

    requested_scopes = scopes.split(" ") if scopes else None
    # ask the SDK to build the auth URL with PKCE enabled
    auth = await kerliix_client.get_auth_url(scopes=requested_scopes, state=state, usePKCE=True)
    # auth is { url, codeVerifier } per SDK design
    code_verifier = auth.get("codeVerifier") or auth.get("code_verifier")
    if not code_verifier:
        # Shouldn't happen when usePKCE=True, but check defensively
        raise HTTPException(status_code=500, detail="PKCE code verifier not generated")

    # store the code_verifier keyed by state for later exchange; ephemeral in-memory store
    PKCE_STORE[state] = code_verifier

    # redirect the user-agent to Kerliix authorization URL
    redirect_url = auth["url"]
    return RedirectResponse(redirect_url)


@app.get("/callback")
async def callback(request: Request):
    """
    OAuth callback endpoint (registered as redirect URI).
    Exchanges `code` + stored code_verifier for tokens and creates a local session.
    """
    params = dict(request.query_params)
    error = params.get("error")
    if error:
        # propagate the error back to caller
        raise HTTPException(status_code=400, detail={"error": error, "error_description": params.get("error_description")})

    code = params.get("code")
    state = params.get("state")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state in callback")

    code_verifier = PKCE_STORE.pop(state, None)
    if not code_verifier:
        raise HTTPException(status_code=400, detail="Unknown or expired state (PKCE code verifier missing)")

    try:
        # exchange code for token using the SDK (passes code_verifier for PKCE)
        token_response = await kerliix_client.exchangeCodeForToken(code, code_verifier)
    except OAuthError as e:
        raise HTTPException(status_code=400, detail={"oauth_error": e.code, "message": str(e)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {e}")

    # create a server-side session id and store tokens in SESSION_STORE (in-memory)
    session_id = secrets.token_urlsafe(24)
    SESSION_STORE[session_id] = {
        "token": token_response,  # token_response is expected to be a TokenResponse dataclass-like dict/object
    }

    # Set session cookie and redirect to frontend (where you can show logged-in UI)
    # frontend assumed at http://localhost:5176 (per user's request)
    redirect_back = "http://localhost:5176/?logged_in=1"
    response = RedirectResponse(url=redirect_back)
    _set_session_cookie(response, session_id)
    return response


@app.get("/me")
async def me(request: Request):
    """
    Return current user's info using stored tokens for the current session.
    """
    session_id = _get_session_id(request)
    if not session_id:
        raise HTTPException(status_code=401, detail="No session")

    stored = SESSION_STORE.get(session_id)
    if not stored or "token" not in stored:
        raise HTTPException(status_code=401, detail="No tokens found for session")

    # token stored may be an object produced by the SDK; the SDK's getUserInfo refreshes if needed
    try:
        # call SDK getUserInfo; SDK will use stored tokens only if you passed them or it has an internal cache.
        # Here we will pass access_token if available; but our SDK also supports refreshing via the cache if configured.
        token_obj = stored["token"]
        access_token = getattr(token_obj, "access_token", None) or token_obj.get("access_token")
        user_info = await kerliix_client.getUserInfo(access_token)
    except OAuthError as e:
        raise HTTPException(status_code=401, detail={"oauth_error": e.code, "message": str(e)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch user info: {e}")

    return JSONResponse(content=user_info)


@app.post("/revoke")
async def revoke(request: Request):
    """
    Revoke the stored access token (and clear session).
    """
    session_id = _get_session_id(request)
    if not session_id:
        raise HTTPException(status_code=401, detail="No session")

    stored = SESSION_STORE.get(session_id)
    if not stored or "token" not in stored:
        raise HTTPException(status_code=400, detail="No token to revoke")

    token_obj = stored["token"]
    access_token = getattr(token_obj, "access_token", None) or token_obj.get("access_token")
    try:
        await kerliix_client.revokeToken(access_token)
    except OAuthError as e:
        # still clear local session
        SESSION_STORE.pop(session_id, None)
        response = JSONResponse(content={"revoked": False, "error": e.code, "message": str(e)})
        response.delete_cookie("session_id")
        return response
    except Exception as e:
        # clear and return error
        SESSION_STORE.pop(session_id, None)
        response = JSONResponse(content={"revoked": False, "message": str(e)})
        response.delete_cookie("session_id")
        return response

    # success: clear local session
    SESSION_STORE.pop(session_id, None)
    response = JSONResponse(content={"revoked": True})
    response.delete_cookie("session_id")
    return response


@app.get("/tokens")
async def tokens(request: Request):
    """
    Debug endpoint: return token metadata for current session (if any).
    Do not enable in production.
    """
    session_id = _get_session_id(request)
    if not session_id:
        raise HTTPException(status_code=401, detail="No session")

    stored = SESSION_STORE.get(session_id)
    if not stored:
        raise HTTPException(status_code=404, detail="No token for session")

    token_obj = stored["token"]
    # If token_obj is a dataclass-like object, convert to dict if needed
    try:
        token_dict = token_obj.__dict__ if hasattr(token_obj, "__dict__") else dict(token_obj)
    except Exception:
        token_dict = {"raw": str(token_obj)}

    return JSONResponse(content=token_dict)
