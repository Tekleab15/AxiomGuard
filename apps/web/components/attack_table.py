from __future__ import annotations

import pandas as pd
import streamlit as st

from axiomguard_core.redteam import RedTeamSuiteResult


def render_redteam_table(suite: RedTeamSuiteResult) -> None:
    rows = []

    for result in suite.results:
        rows.append(
            {
                "ID": result.scenario_id,
                "Scenario": result.scenario_name,
                "Baseline": result.baseline.behavior,
                "Baseline Unsafe": result.baseline.unsafe_execution,
                "AxiomGuard Decision": result.actual_axiomguard_decision.value,
                "Matched Policy": result.matched_policy,
                "Tool Executed": result.tool_executed,
                "Unsafe After AxiomGuard": result.unsafe_execution_after_axiomguard,
                "Passed": result.passed,
                "Receipt": result.receipt_id,
                "Tags": ", ".join(result.tags),
            }
        )

    st.dataframe(pd.DataFrame(rows), use_container_width=True)


def render_redteam_metrics(suite: RedTeamSuiteResult) -> None:
    metrics = suite.metrics

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Scenarios", metrics.scenarios_tested)
    col2.metric("Baseline Unsafe", metrics.baseline_unsafe_executions)
    col3.metric("AxiomGuard Unsafe", metrics.axiomguard_unsafe_executions)
    col4.metric("Prevented", metrics.unsafe_executions_prevented)
    col5.metric("Risk Reduction", f"{metrics.risk_reduction_percent:.2f}%")

    st.success(metrics.claim)