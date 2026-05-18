from __future__ import annotations

from pathlib import Path

import json
import streamlit as st


def render_home_metrics() -> None:
    result_path = Path("data/redteam/axiomguard_results.json")

    if result_path.exists():
        data = json.loads(result_path.read_text(encoding="utf-8"))
        metrics = data.get("metrics", {})
    else:
        metrics = {
            "scenarios_tested": 0,
            "baseline_unsafe_executions": 0,
            "axiomguard_unsafe_executions": 0,
            "risk_reduction_percent": 0.0,
            "decision_receipts_generated": 0,
        }

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Scenarios Tested", metrics.get("scenarios_tested", 0))
    col2.metric("Baseline Unsafe", metrics.get("baseline_unsafe_executions", 0))
    col3.metric("AxiomGuard Unsafe", metrics.get("axiomguard_unsafe_executions", 0))
    col4.metric("Risk Reduction", f"{metrics.get('risk_reduction_percent', 0):.2f}%")
    col5.metric("Receipts", metrics.get("decision_receipts_generated", 0))


def render_decision_banner(decision: str) -> None:
    if decision == "ALLOW":
        st.success("✅ Final Decision: ALLOW — execution authorized by valid Decision Receipt.")
    elif decision == "DENY":
        st.error("⛔ Final Decision: DENY — execution blocked.")
    elif decision == "QUARANTINE":
        st.error("🚨 Final Decision: QUARANTINE — security review required.")
    elif decision == "HUMAN_REVIEW":
        st.warning("👤 Final Decision: HUMAN_REVIEW — manager or compliance approval required.")
    elif decision == "REDACT":
        st.warning("🧹 Final Decision: REDACT — sensitive fields must be removed.")
    else:
        st.info(f"Final Decision: {decision}")


def render_pipeline_summary(summary: dict) -> None:
    render_decision_banner(summary["final_decision"])

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Matched Policy", summary["matched_policy"])
    col2.metric("Executed", str(summary["executed"]))
    col3.metric("Risk Score", summary["lobstertrap"]["risk_score"])
    col4.metric("Contradiction Loss", summary["lnn"]["contradiction_loss"])

    with st.expander("Decision Reason", expanded=True):
        st.write(summary["reason"])

    if summary.get("safe_alternative"):
        with st.expander("Safe Alternative", expanded=True):
            st.write(summary["safe_alternative"])