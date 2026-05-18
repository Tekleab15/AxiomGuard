from __future__ import annotations

import streamlit as st


def render_architecture_panel() -> None:
    st.markdown("## Runtime Architecture")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.info("**Planner**\n\nGemini or MockPlanner converts user intent into ActionScript JSON.")

    with col2:
        st.warning("**Inspection**\n\nLobster Trap metadata captures injection, exfiltration, PII, and risk.")

    with col3:
        st.success("**AxiomLNN**\n\nLogical formulas infer ALLOW, DENY, QUARANTINE, or HUMAN_REVIEW.")

    with col4:
        st.error("**Gate**\n\nDeterministic enforcement blocks unsafe tool execution.")

    with col5:
        st.info("**Receipt**\n\nHashed Decision Receipt proves what happened and why.")

    st.code(
        """
User Request + Document
        ↓
Gemini / MockPlanner → ActionScript
        ↓
Lobster Trap Findings
        ↓
AxiomLNN Verification
        ↓
Deterministic Gate
        ↓
Decision Receipt
        ↓
Receipt-Required Tool Execution
        """.strip(),
        language="text",
    )