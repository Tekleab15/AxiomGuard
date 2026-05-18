from __future__ import annotations

import streamlit as st


def apply_global_styles() -> None:
    st.markdown(
        """
        <style>
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
            max-width: 1400px;
        }

        div[data-testid="stMetric"] {
            background: linear-gradient(180deg, rgba(30,41,59,0.08), rgba(15,23,42,0.03));
            border: 1px solid rgba(148,163,184,0.25);
            padding: 1rem;
            border-radius: 16px;
        }

        div[data-testid="stMetricLabel"] {
            font-weight: 700;
        }

        .axiom-card {
            border: 1px solid rgba(148,163,184,0.28);
            border-radius: 18px;
            padding: 1.1rem 1.25rem;
            background: rgba(15,23,42,0.035);
            margin-bottom: 1rem;
        }

        .axiom-hero {
            padding: 1.25rem 1.4rem;
            border-radius: 20px;
            background: linear-gradient(135deg, rgba(30,64,175,0.16), rgba(14,165,233,0.10));
            border: 1px solid rgba(59,130,246,0.25);
            margin-bottom: 1rem;
        }

        .axiom-small {
            font-size: 0.92rem;
            color: rgba(100,116,139,1);
        }

        .axiom-badge {
            display: inline-block;
            padding: 0.25rem 0.55rem;
            margin-right: 0.35rem;
            border-radius: 999px;
            background: rgba(15,23,42,0.08);
            border: 1px solid rgba(148,163,184,0.35);
            font-size: 0.82rem;
            font-weight: 650;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero() -> None:
    st.markdown(
        """
        <div class="axiom-hero">
          <h1 style="margin-bottom:0.2rem;">🛡️ AxiomGuard</h1>
          <h3 style="margin-top:0;">Tamper-evident governance for enterprise AI agents</h3>
          <p class="axiom-small">
            Gemini plans. Lobster Trap inspects. AxiomLNN verifies. The deterministic gate enforces.
            Only valid ALLOW Decision Receipts can execute tools.
          </p>
          <span class="axiom-badge">Agent Security</span>
          <span class="axiom-badge">AI Governance</span>
          <span class="axiom-badge">Decision Receipts</span>
          <span class="axiom-badge">AxiomLNN</span>
          <span class="axiom-badge">OWASP Mapping</span>
        </div>
        """,
        unsafe_allow_html=True,
    )