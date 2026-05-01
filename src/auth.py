"""
Microsoft Graph API authentication using MSAL.
Handles OAuth2 device code + web (redirect) flows.
"""

import os
import msal
import streamlit as st
from typing import Optional

TENANT_ID = os.getenv("AZURE_TENANT_ID", "common")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8501/callback")

SCOPES = [
    "https://graph.microsoft.com/Files.Read.All",
    "https://graph.microsoft.com/Sites.Read.All",
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
    "https://graph.microsoft.com/Group.Read.All",
]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"


def get_msal_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
    )


def get_auth_url() -> str:
    """Generate Microsoft OAuth2 authorization URL."""
    app = get_msal_app()
    return app.get_authorization_request_url(
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=os.urandom(16).hex(),
    )


def exchange_code_for_token(code: str) -> Optional[dict]:
    """Exchange auth code for access token."""
    app = get_msal_app()
    result = app.acquire_token_by_authorization_code(
        code=code,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    if "access_token" in result:
        return result
    return None


def get_token_from_session() -> Optional[str]:
    """Retrieve stored access token from Streamlit session."""
    return st.session_state.get("access_token")


def store_token_in_session(token_result: dict):
    """Store token result in Streamlit session state."""
    st.session_state["access_token"] = token_result.get("access_token")
    st.session_state["id_token_claims"] = token_result.get("id_token_claims", {})
    user_name = token_result.get("id_token_claims", {}).get("name", "Unknown")
    tenant = token_result.get("id_token_claims", {}).get("tid", "Unknown")
    st.session_state["user_name"] = user_name
    st.session_state["tenant_id"] = tenant


def is_authenticated() -> bool:
    return bool(st.session_state.get("access_token"))


def logout():
    for key in ["access_token", "id_token_claims", "user_name", "tenant_id", "scan_results"]:
        st.session_state.pop(key, None)
