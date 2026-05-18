from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[3]
WEB_DIR = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from axiomguard_core.redteam import (
    run_redteam_suite,
    save_redteam_markdown_report,
    save_redteam_results,
    suite_to_markdown,
)

from components.attack_table import render_redteam_metrics, render_redteam_table


st.set_page_config(page_title="AxiomGuard Red-Team Replay", page_icon="🔥", layout="wide")

st.title("🔥 Red-Team Replay")
st.caption("Baseline vs AxiomGuard protection with measurable risk-reduction metrics.")

persist_receipts = st.checkbox("Persist receipts for each scenario", value=True)

if st.button("Run Red-Team Suite", type="primary"):
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=persist_receipts,
        receipt_directory="data/receipts/generated",
    )

    json_path = save_redteam_results(suite, "data/redteam/axiomguard_results.json")
    md_path = save_redteam_markdown_report(suite, "data/redteam/redteam_report.md")

    st.session_state["redteam_suite"] = suite
    st.success(f"Saved results to {json_path} and {md_path}.")


if "redteam_suite" in st.session_state:
    suite = st.session_state["redteam_suite"]

    render_redteam_metrics(suite)
    render_redteam_table(suite)

    with st.expander("Judge-Readable Markdown Report"):
        st.markdown(suite_to_markdown(suite))
else:
    st.info("Run the red-team suite to generate metrics and Decision Receipts.")