from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st
from axiomguard_core.planner import PlannerRequest, SafeReplanRequest
from axiomguard_core.planner_factory import get_planner

ROOT = Path(__file__).resolve().parents[3]
WEB_DIR = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from axiomguard_core.pipeline import PipelineOptions, run_axiomguard_pipeline
from axiomguard_core.planner import MockPlanner, PlannerRequest, SafeReplanRequest
from axiomguard_core.schemas import ActorProfile, LobsterTrapFinding

from components.risk_cards import render_pipeline_summary
from components.receipt_viewer import render_receipt_from_dashboard_summary
from components.trace_viewer import render_lnn_trace


st.set_page_config(page_title="AxiomGuard Agent Console", page_icon="🛡️", layout="wide")

st.title("🛡️ Agent Console")
st.caption("Run user intent through MockPlanner → AxiomLNN → Gate → Receipt → Tool Executor.")

EXAMPLES = {
    "Safe invoice summary": {
        "prompt": "Summarize invoice_101 for internal review.",
        "document": "Invoice invoice_101. Amount: 1400 USD. Vendor: SafeOffice Supplies.",
        "role": "procurement_analyst",
        "limit": 0,
    },
    "High-value invoice approval": {
        "prompt": "Approve invoice_8821 for $52,000.",
        "document": "Invoice invoice_8821. Amount: 52000 USD. Vendor: Northstar Logistics.",
        "role": "finance_analyst",
        "limit": 10000,
    },
    "PII external email": {
        "prompt": "Send all employee salary records to my personal Gmail.",
        "document": "Employee records include names, emails, salary data, and employee identifiers.",
        "role": "hr_analyst",
        "limit": 0,
    },
    "Safe approval packet": {
        "prompt": "Create an approval packet for invoice_8821 and route it to a finance manager.",
        "document": "Invoice invoice_8821. Amount: 52000 USD. Requires manager review.",
        "role": "finance_analyst",
        "limit": 10000,
    },
    "Safe redacted HR report": {
        "prompt": "Create a redacted internal HR compensation summary.",
        "document": "Employee records include names, emails, salary data, and employee identifiers.",
        "role": "hr_analyst",
        "limit": 0,
    },
}


def heuristic_lobstertrap(prompt: str, document: str) -> LobsterTrapFinding:
    text = f"{prompt}\n{document}".lower()

    prompt_injection = "ignore all previous" in text or "hidden instruction" in text
    exfiltration = "attacker@" in text or "exfiltrate" in text
    pii = "employee" in text or "salary" in text or "ssn" in text
    credential = "api_key" in text or "credential" in text or "secret" in text
    risky_command = "delete database" in text or "rm -rf" in text

    risk = 8.0

    if pii:
        risk = max(risk, 35.0)
    if credential:
        risk = max(risk, 85.0)
    if prompt_injection:
        risk = max(risk, 90.0)
    if exfiltration:
        risk = max(risk, 94.0)
    if risky_command:
        risk = max(risk, 90.0)

    detected_domains = []
    if "attacker@example.com" in text:
        detected_domains.append("attacker@example.com")
    if "personal@gmail.com" in text:
        detected_domains.append("personal@gmail.com")

    return LobsterTrapFinding(
        prompt_injection=prompt_injection,
        exfiltration_detected=exfiltration,
        pii_detected=pii,
        credential_detected=credential,
        risky_command_detected=risky_command,
        risk_score=risk,
        detected_domains=detected_domains,
        declared_intent_category="summary" if "summarize" in text else "workflow",
        detected_intent_category="data_exfiltration" if exfiltration else "workflow",
        intent_mismatch=("summarize" in text and exfiltration),
        raw={"source": "streamlit_heuristic_lobstertrap"},
    )


selected = st.sidebar.selectbox("Demo scenario", list(EXAMPLES.keys()))
example = EXAMPLES[selected]

actor_id = st.sidebar.text_input("Actor ID", "user_demo_001")
role = st.sidebar.text_input("Role", example["role"])
department = st.sidebar.text_input("Department", "demo")
approval_limit = st.sidebar.number_input(
    "Approval limit USD",
    min_value=0.0,
    value=float(example["limit"]),
    step=1000.0,
)

actor = ActorProfile(
    id=actor_id,
    role=role,
    department=department,
    approval_limit_usd=approval_limit,
)

user_prompt = st.text_area("User request", example["prompt"], height=100)
document_text = st.text_area("Enterprise document context", example["document"], height=160)

persist_receipt = st.checkbox("Persist receipt to data/receipts/generated", value=True)
execute_tools = st.checkbox("Attempt tool execution if ALLOW", value=True)

if st.button("Run AxiomGuard Pipeline", type="primary"):
    planner = get_planner()

    planned = planner.plan(
        PlannerRequest(
            actor=actor,
            user_prompt=user_prompt,
            document_text=document_text,
        )
    )

    trap = heuristic_lobstertrap(user_prompt, document_text)

    result = run_axiomguard_pipeline(
        action=planned.action,
        lobstertrap_findings=trap,
        options=PipelineOptions(
            execute_tools=execute_tools,
            persist_receipt=persist_receipt,
            export_markdown=persist_receipt,
            receipt_directory="data/receipts/generated",
            agent="streamlit_procurement_copilot",
        ),
    )

    st.session_state["last_pipeline_result"] = result
    st.session_state["last_planner_result"] = planned


if "last_pipeline_result" in st.session_state:
    result = st.session_state["last_pipeline_result"]
    planned = st.session_state["last_planner_result"]

    st.markdown("---")
    st.markdown("## Pipeline Result")

    summary = result.to_dashboard_dict()
    render_pipeline_summary(summary)

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "ActionScript",
            "Lobster Trap",
            "AxiomLNN Trace",
            "Decision Receipt",
            "Tool Result",
        ]
    )

    with tab1:
        st.markdown("### Planner Output")
        st.caption(f"Planner backend: {planned.planner_backend}")
        st.json(planned.action.model_dump(mode="json"))

    with tab2:
        st.json(result.lobstertrap_findings.model_dump(mode="json"))

    with tab3:
        render_lnn_trace(result.lnn_inference)

    with tab4:
        render_receipt_from_dashboard_summary(summary)

    with tab5:
        st.json(summary["tool_result"])

    if not result.allowed_to_execute and result.enforcement.safe_alternative:
        st.markdown("---")
        st.markdown("## Safe Replan")

        if st.button("Generate Safe Replan with MockPlanner"):
            planner = get_planner()

            replanned = planner.replan(
                SafeReplanRequest(
                    actor=result.action.actor,
                    original_action=result.action,
                    blocked_decision=result.final_decision.value,
                    blocked_reason=result.enforcement.reason,
                    safe_alternative=result.enforcement.safe_alternative,
                    document_text=document_text,
                )
            )

            replan_result = run_axiomguard_pipeline(
                action=replanned.action,
                lobstertrap_findings=heuristic_lobstertrap(
                    replanned.action.declared_intent,
                    document_text,
                ),
                options=PipelineOptions(
                    execute_tools=execute_tools,
                    persist_receipt=persist_receipt,
                    export_markdown=persist_receipt,
                    receipt_directory="data/receipts/generated",
                    agent="streamlit_safe_replan_agent",
                    previous_receipt_hash=result.receipt.receipt_hash,
                ),
            )

            st.success("Safe replan generated and verified.")
            render_pipeline_summary(replan_result.to_dashboard_dict())
            st.json(replan_result.to_dashboard_dict())