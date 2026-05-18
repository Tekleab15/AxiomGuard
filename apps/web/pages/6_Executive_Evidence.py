from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[3]
WEB_DIR = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from axiomguard_core.evidence import (
    build_receipt_chain,
    generate_executive_summary,
    save_judge_report,
    save_owasp_coverage,
)
from axiomguard_core.redteam import (
    run_redteam_suite,
    save_redteam_results,
)


st.set_page_config(
    page_title="AxiomGuard Executive Evidence",
    page_icon="🏆",
    layout="wide",
)

st.title("🏆 Executive Evidence")
st.caption(
    "Judge-ready proof that AxiomGuard is an enterprise AI governance control plane."
)

st.markdown(
    """
    This page turns AxiomGuard's red-team results into executive evidence:
    
    - measurable unsafe-execution reduction
    - OWASP LLM risk coverage
    - matched policy coverage
    - tamper-evident receipt timeline
    - CISO-ready compliance export
    """
)

if st.button("Generate Evidence Pack", type="primary"):
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=True,
        receipt_directory="data/receipts/generated",
    )

    save_redteam_results(suite, "data/redteam/axiomguard_results.json")
    report_path = save_judge_report(suite)
    coverage_path = save_owasp_coverage(suite)

    st.session_state["executive_suite"] = suite

    st.success(f"Generated evidence pack: {report_path}")
    st.success(f"Generated OWASP coverage: {coverage_path}")


if "executive_suite" not in st.session_state:
    result_path = Path("data/redteam/axiomguard_results.json")

    if result_path.exists():
        suite = run_redteam_suite(
            scenario_path="data/redteam/attacks.json",
            persist_receipts=False,
        )
        st.session_state["executive_suite"] = suite
    else:
        st.info("Click **Generate Evidence Pack** to create executive metrics.")
        st.stop()


suite = st.session_state["executive_suite"]
summary = generate_executive_summary(suite)

st.success(summary["headline"])
st.caption(summary["disclaimer"])

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Scenarios Tested", summary["scenarios_tested"])
col2.metric("Baseline Unsafe", summary["baseline_unsafe_executions"])
col3.metric("AxiomGuard Unsafe", summary["axiomguard_unsafe_executions"])
col4.metric("Risk Reduction", f"{summary['risk_reduction_percent']:.2f}%")
col5.metric("Receipts", summary["decision_receipts_generated"])

st.markdown("---")

st.markdown("## OWASP LLM Risk Coverage")

coverage_rows = [
    {
        "OWASP Risk": risk,
        "Scenario Count": count,
        "Enterprise Context": summary["owasp_coverage"]["descriptions"].get(risk, ""),
    }
    for risk, count in summary["owasp_coverage"]["coverage"].items()
]

if coverage_rows:
    st.dataframe(pd.DataFrame(coverage_rows), use_container_width=True)
else:
    st.info("No OWASP risk mappings found.")

st.markdown("## Top Matched Policies")

policy_rows = [
    {"Policy": policy, "Count": count}
    for policy, count in summary["top_policies"]
]

if policy_rows:
    st.dataframe(pd.DataFrame(policy_rows), use_container_width=True)
else:
    st.info("No policy coverage found.")

st.markdown("## Decision Distribution")

decision_rows = [
    {"Decision": decision, "Count": count}
    for decision, count in summary["top_decisions"]
]

if decision_rows:
    decision_df = pd.DataFrame(decision_rows)
    st.bar_chart(decision_df.set_index("Decision"))

st.markdown("## Receipt Chain Timeline")

chain = build_receipt_chain("data/receipts/generated")

if chain:
    chain_df = pd.DataFrame(chain)
    st.dataframe(chain_df, use_container_width=True)

    invalid_hashes = chain_df[chain_df["hash_valid"] == False]

    if invalid_hashes.empty:
        st.success("All loaded Decision Receipts passed hash verification.")
    else:
        st.error("One or more Decision Receipts failed hash verification.")
        st.dataframe(invalid_hashes, use_container_width=True)
else:
    st.info("No generated receipts found yet. Generate the Evidence Pack first.")

st.markdown("## CISO Compliance Export Pack")

report_path = Path("data/redteam/AxiomGuard_CISO_Compliance_Report.md")
json_path = Path("data/redteam/axiomguard_results.json")
owasp_path = Path("data/redteam/owasp_coverage.json")

download_col1, download_col2, download_col3 = st.columns(3)

with download_col1:
    if report_path.exists():
        st.download_button(
            label="📥 Download CISO Compliance Report",
            data=report_path.read_text(encoding="utf-8"),
            file_name="AxiomGuard_CISO_Compliance_Report.md",
            mime="text/markdown",
        )
    else:
        st.info("Generate the evidence pack first.")

with download_col2:
    if json_path.exists():
        st.download_button(
            label="📥 Download Red-Team Evidence JSON",
            data=json_path.read_text(encoding="utf-8"),
            file_name="AxiomGuard_RedTeam_Evidence.json",
            mime="application/json",
        )
    else:
        st.info("Run red-team replay first.")

with download_col3:
    if owasp_path.exists():
        st.download_button(
            label="📥 Download OWASP Coverage JSON",
            data=owasp_path.read_text(encoding="utf-8"),
            file_name="AxiomGuard_OWASP_Coverage.json",
            mime="application/json",
        )
    else:
        st.info("Generate OWASP coverage first.")