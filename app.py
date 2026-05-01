"""
Copilot Data Exposure Firewall — Streamlit App
Connects to Microsoft 365 via read-only Graph API and maps Copilot's blast radius.
"""

import os
import streamlit as st
from urllib.parse import urlencode, parse_qs, urlparse
from dotenv import load_dotenv

load_dotenv()

from src.auth import (
    get_auth_url, exchange_code_for_token, store_token_in_session,
    get_token_from_session, is_authenticated, logout
)
from src.graph_client import GraphClient
from src.scanner import run_scan, ScanResult, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM
from src.report_generator import generate_pdf

# --- Page config ---
st.set_page_config(
    page_title="Copilot Firewall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# --- CSS ---
st.markdown("""
<style>
  .risk-critical { background:#FEE2E2; color:#991B1B; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px; }
  .risk-high { background:#FFEDD5; color:#9A3412; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px; }
  .risk-medium { background:#FEF9C3; color:#854D0E; padding:4px 10px; border-radius:6px; font-weight:700; font-size:12px; }
  .score-circle { font-size:72px; font-weight:800; line-height:1; }
  .metric-box { background:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; text-align:center; }
  .finding-row { border-left:4px solid; padding:10px 14px; margin:6px 0; border-radius:0 8px 8px 0; background:#FAFAFA; }
</style>
""", unsafe_allow_html=True)


# ============================================================
# AUTH FLOW
# ============================================================

def handle_oauth_callback():
    """Pick up ?code= from Microsoft redirect."""
    query_params = st.query_params
    code = query_params.get("code")
    if code and not is_authenticated():
        with st.spinner("Authenticating with Microsoft…"):
            token = exchange_code_for_token(code)
            if token:
                store_token_in_session(token)
                st.query_params.clear()
                st.rerun()
            else:
                st.error("Authentication failed — please try again.")


def render_login():
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("## 🛡️ Copilot Data Exposure Firewall")
        st.markdown("#### See exactly what Microsoft Copilot can read in your tenant — in 15 minutes.")
        st.markdown("")
        st.info(
            "**Read-only access only.** We request `Files.Read.All`, `Sites.Read.All`, "
            "`User.Read.All`, and `Directory.Read.All`. No files are stored — only permission metadata.",
            icon="🔒"
        )
        st.markdown("")
        auth_url = get_auth_url()
        st.markdown(
            f'<a href="{auth_url}" target="_self">'
            f'<button style="background:#2563EB;color:white;border:none;padding:14px 28px;'
            f'border-radius:8px;font-size:16px;font-weight:700;cursor:pointer;width:100%">'
            f'🔐 Sign in with Microsoft 365</button></a>',
            unsafe_allow_html=True
        )
        st.markdown("")
        st.markdown(
            "<small>By continuing you agree to our read-only scan. "
            "No files are modified or stored. Results expire after 24 hours.</small>",
            unsafe_allow_html=True
        )


# ============================================================
# SCAN FLOW
# ============================================================

def render_scan_trigger():
    user_name = st.session_state.get("user_name", "User")
    tenant_id = st.session_state.get("tenant_id", "")

    st.markdown(f"## Welcome, {user_name} 👋")
    st.markdown(f"**Tenant:** `{tenant_id[:8]}…`")
    st.markdown("---")

    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("### What this scan checks")
        st.markdown("""
- 🔴 **Anonymous sharing links** — anyone with the URL can access
- 🟠 **Org-wide links** — all 365 users (+ Copilot) can read
- 🟡 **Sensitive folders** with stale permissions (HR, Finance, Legal, Payroll, Credentials)
- 📊 **AI Readiness Score** — 0–100 grade of your Copilot data governance posture
        """)
    with col2:
        st.markdown("### Estimated time")
        st.metric("Typical scan time", "8–15 min", help="Depends on tenant size")
        st.metric("Items scanned", "All SharePoint sites", help="Read-only Graph API")

    st.markdown("")
    if st.button("🚀 Start Scan", type="primary", use_container_width=True):
        run_scan_with_progress()

    st.markdown("---")
    if st.button("Sign out", type="secondary"):
        logout()
        st.rerun()


def run_scan_with_progress():
    token = get_token_from_session()
    client = GraphClient(access_token=token)

    progress_bar = st.progress(0)
    status_text = st.empty()

    def on_progress(step: str, pct: int):
        progress_bar.progress(pct / 100)
        status_text.text(step)

    with st.spinner(""):
        result = run_scan(client, progress_callback=on_progress)

    progress_bar.empty()
    status_text.empty()
    st.session_state["scan_results"] = result
    st.rerun()


# ============================================================
# RESULTS FLOW
# ============================================================

def render_results(result: ScanResult):
    st.markdown("## 🛡️ Copilot Exposure Report")
    st.markdown(f"*Scanned {result.total_items_scanned:,} items across {result.total_sites} sites · {result.scanned_at[:10]}*")
    st.markdown("---")

    col1, col2, col3, col4, col5 = st.columns(5)
    grade_colors = {"A": "#16A34A", "B": "#2563EB", "C": "#CA8A04", "D": "#EA580C", "F": "#DC2626"}
    gc = grade_colors.get(result.risk_grade, "#DC2626")

    with col1:
        st.markdown(
            f'<div class="metric-box"><div class="score-circle" style="color:{gc}">{result.risk_grade}</div>'
            f'<div style="font-size:13px;color:#64748B">AI Readiness Grade</div></div>',
            unsafe_allow_html=True
        )
    with col2:
        st.metric("Readiness Score", f"{result.ai_readiness_score}/100")
    with col3:
        st.metric("🔴 Critical", len(result.critical_items))
    with col4:
        st.metric("🟠 High", len(result.high_items))
    with col5:
        st.metric("🟡 Medium", len(result.medium_items))

    st.markdown("---")

    with st.expander("📊 Score breakdown", expanded=False):
        for label, detail in result.score_breakdown.items():
            st.markdown(f"- **{label}:** {detail}")

    tab1, tab2, tab3 = st.tabs(
        [f"🔴 Critical ({len(result.critical_items)})",
         f"🟠 High ({len(result.high_items)})",
         f"🟡 Medium ({len(result.medium_items)})"]
    )

    def render_items(items, border_color):
        if not items:
            st.success("No issues in this category.")
            return
        for item in items:
            with st.container():
                cols = st.columns([3, 2, 2, 3])
                with cols[0]:
                    st.markdown(f"**{item.name}**")
                    st.caption(item.site_name)
                with cols[1]:
                    st.markdown(f"**Permission:** `{item.permission_type}`")
                    st.caption(f"Granted to: {item.granted_to}")
                with cols[2]:
                    st.markdown(f"**Modified:** {(item.last_modified or '')[:10]}")
                    st.caption("📁 Folder" if item.is_folder else "📄 File")
                with cols[3]:
                    for reason in item.risk_reasons:
                        st.warning(reason, icon="⚠️")
                with st.expander("🔧 Remediation"):
                    st.code(item.remediation, language="powershell")
                st.markdown("")

    with tab1:
        render_items(result.critical_items, "#DC2626")
    with tab2:
        render_items(result.high_items, "#EA580C")
    with tab3:
        render_items(result.medium_items, "#CA8A04")

    st.markdown("---")
    st.markdown("### 📄 Download Report")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("📥 Free Preview (3 findings, redacted)", use_container_width=True):
            pdf_bytes = generate_pdf(result, redact_after=3)
            st.download_button(
                label="⬇️ Download Preview PDF",
                data=pdf_bytes,
                file_name="copilot-exposure-preview.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

    with col2:
        st.markdown(
            "**Full Report + Remediation Playbook — $999**  \n"
            "Includes all findings, PowerShell fix scripts, and CISO-ready PDF.  \n"
            "[👉 Unlock Full Report](https://buy.stripe.com/your-link-here)",
            unsafe_allow_html=True
        )

    if result.errors:
        with st.expander(f"⚠️ Scan warnings ({len(result.errors)})", expanded=False):
            for err in result.errors:
                st.caption(err)

    st.markdown("---")
    cols = st.columns([1, 1, 4])
    with cols[0]:
        if st.button("🔄 Re-scan", use_container_width=True):
            del st.session_state["scan_results"]
            st.rerun()
    with cols[1]:
        if st.button("Sign out", use_container_width=True):
            logout()
            st.rerun()


# ============================================================
# MAIN ROUTER
# ============================================================

def main():
    handle_oauth_callback()

    if not is_authenticated():
        render_login()
    elif "scan_results" in st.session_state:
        render_results(st.session_state["scan_results"])
    else:
        render_scan_trigger()


if __name__ == "__main__":
    main()
