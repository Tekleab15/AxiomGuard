from __future__ import annotations

import pandas as pd
import streamlit as st

from axiomguard_core.schemas import AxiomLNNInference


def render_lnn_trace(inference: AxiomLNNInference) -> None:
    st.markdown("## AxiomLNN Verification Trace")

    col1, col2, col3, col4, col5, col6 = st.columns(6)

    col1.metric("Allow", f"{inference.allow.lower:.2f}")
    col2.metric("Deny", f"{inference.deny.lower:.2f}")
    col3.metric("Quarantine", f"{inference.quarantine.lower:.2f}")
    col4.metric("Human Review", f"{inference.human_review.lower:.2f}")
    col5.metric("Redact", f"{inference.redact.lower:.2f}")
    col6.metric("Contradiction", f"{inference.contradiction_loss:.2f}")

    formulas = [
        {
            "Policy": formula.policy_id,
            "Decision": formula.decision.value,
            "Score": formula.score,
            "Formula": formula.formula,
            "Trace": formula.trace,
        }
        for formula in inference.matched_formulas
    ]

    st.markdown("### Matched Formula Trace")

    if formulas:
        st.dataframe(pd.DataFrame(formulas), use_container_width=True)
    else:
        st.info("No policy formulas matched above zero confidence.")

    with st.expander("Full AxiomLNN Trace", expanded=True):
        st.code(inference.trace, language="text")

    with st.expander("Extracted Facts"):
        st.json(inference.facts)