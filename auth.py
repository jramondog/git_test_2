import os
import json
from typing import Optional, Dict

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials

# Scopes required for basic user info
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

# Path to the OAuth 2.0 client configuration file (downloaded from Google Cloud Console)
CLIENT_SECRETS_FILE = os.getenv("GOOGLE_CLIENT_SECRETS", "client_secret.json")


def _initialize_flow(redirect_uri: str) -> Flow:
    """Create a Flow instance for Google OAuth 2.0.

    Args:
        redirect_uri: The URI Google should redirect to after authentication.

    Returns:
        An initialized :class:`google_auth_oauthlib.flow.Flow` object.
    """
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )


def get_login_url(redirect_uri: str) -> str:
    """Generate a Google login URL.

    The caller should redirect the user to this URL. After the user consents,
    Google will redirect back to ``redirect_uri`` with a ``code`` query
    parameter, which can be exchanged for credentials via :func:`fetch_token`.

    Args:
        redirect_uri: The callback URL registered in the Google Cloud project.

    Returns:
        A URL string that can be used to start the OAuth flow.
    """
    flow = _initialize_flow(redirect_uri)
    auth_url, _ = flow.authorization_url(prompt="consent", include_granted_scopes="true")
    return auth_url


def fetch_token(code: str, redirect_uri: str) -> Credentials:
    """Exchange an authorization *code* for Google OAuth credentials.

    Args:
        code: The authorization code received from Google.
        redirect_uri: Must match the URI used when generating the login URL.

    Returns:
        A :class:`google.oauth2.credentials.Credentials` object containing
        access and refresh tokens.
    """
    flow = _initialize_flow(redirect_uri)
    flow.fetch_token(code=code)
    return flow.credentials


def login(redirect_uri: str, code: Optional[str] = None) -> Dict[str, str]:
    """Convenient wrapper for Google login.

    * If ``code`` is ``None``, the function returns a dictionary with a
      ``login_url`` key that the caller should redirect the user to.
    * If ``code`` is provided, it exchanges the code for tokens and returns a
      dictionary containing ``access_token``, ``refresh_token`` and ``id_token``.

    Args:
        redirect_uri: The OAuth2 callback URL.
        code: Optional authorization code from Google.

    Returns:
        A mapping with either ``login_url`` or token information.
    """
    if code is None:
        return {"login_url": get_login_url(redirect_uri)}
    creds = fetch_token(code, redirect_uri)
    return {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "id_token": creds.id_token,
        "expiry": creds.expiry.isoformat() if creds.expiry else None,
    }
