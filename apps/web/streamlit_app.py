from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st
from styles import apply_global_styles, render_hero

apply_global_styles()
render_hero()

ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from components.architecture_panel import render_architecture_panel
from components.risk_cards import render_home_metrics


st.set_page_config(
    page_title="AxiomGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ AxiomGuard")
st.subheader("Decision Receipts for LNN-Governed Enterprise AI Agents")

st.markdown(
    """
    **Gemini plans. Lobster Trap inspects. AxiomLNN verifies. Only approved actions execute.**

    AxiomGuard is a zero-trust control plane for enterprise AI agents. It converts proposed
    agent actions into auditable, policy-checked Decision Receipts before execution.
    """
)

render_home_metrics()
render_architecture_panel()

st.markdown("---")

st.markdown(
    """
    ### Winning Demo Flow

    1. Open **Agent Console** and run a safe invoice summary.
    2. Run a high-value invoice approval request and watch AxiomGuard route it to human review.
    3. Run a PII exfiltration or prompt-injection scenario and watch it block execution.
    4. Open **Decision Receipts** to inspect the audit trail.
    5. Open **Red-Team Replay** to generate measurable risk-reduction metrics.
    6. Open **AxiomLNN Trace** to show formula-level explainability.
    """
)