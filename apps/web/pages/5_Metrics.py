from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[3]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


st.set_page_config(page_title="AxiomGuard Metrics", page_icon="📊", layout="wide")

st.title("📊 Metrics")
st.caption("Risk reduction, decisions, matched policies, and red-team coverage.")

path = Path("data/redteam/axiomguard_results.json")

if not path.exists():
    st.warning("No red-team results found yet. Run the Red-Team Replay page first.")
    st.stop()

data = json.loads(path.read_text(encoding="utf-8"))
metrics = data["metrics"]

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Scenarios", metrics["scenarios_tested"])
col2.metric("Baseline Unsafe", metrics["baseline_unsafe_executions"])
col3.metric("AxiomGuard Unsafe", metrics["axiomguard_unsafe_executions"])
col4.metric("Risk Reduction", f"{metrics['risk_reduction_percent']:.2f}%")
col5.metric("Pass Rate", f"{metrics['pass_rate_percent']:.2f}%")

st.success(metrics["claim"])

st.markdown("## Decisions")
decision_df = pd.DataFrame(
    [{"Decision": key, "Count": value} for key, value in metrics["decisions"].items()]
)

if not decision_df.empty:
    st.bar_chart(decision_df.set_index("Decision"))

st.markdown("## Matched Policies")
policy_df = pd.DataFrame(
    [{"Policy": key, "Count": value} for key, value in metrics["matched_policies"].items()]
)

if not policy_df.empty:
    st.bar_chart(policy_df.set_index("Policy"))

st.markdown("## Tags Covered")
tag_df = pd.DataFrame(
    [{"Tag": key, "Count": value} for key, value in metrics["tags"].items()]
)

if not tag_df.empty:
    st.dataframe(tag_df.sort_values("Count", ascending=False), use_container_width=True)

st.markdown("## Raw Metrics")
st.json(metrics)