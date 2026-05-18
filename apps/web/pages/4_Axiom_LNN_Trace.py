from __future__ import annotations

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

from axiomguard_core.enforcer import DeterministicGate
from axiomguard_core.redteam import (
    build_action_and_findings_for_scenario,
    load_redteam_scenarios,
)
from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    ActorProfile,
    DataClass,
    DestinationType,
    LobsterTrapFinding,
    RiskSignal,
    ToolName,
)
from axiomguard_core.verifier import verify_action

from components.trace_viewer import render_lnn_trace
from components.risk_cards import render_decision_banner


def _build_sandbox_action(
    *,
    actor: ActorProfile,
    declared_safe: bool,
    action_kind: str,
    external_destination: bool,
    pii_detected: bool,
    credential_detected: bool,
    amount_usd: float | None,
) -> ActionScript:
    """
    Build a sandbox ActionScript from UI controls.
    """

    action_type = ActionType(action_kind)

    tool_by_action = {
        ActionType.SUMMARIZE_CONTRACT: ToolName.DOCS_SUMMARIZE,
        ActionType.SEND_EMAIL: ToolName.EMAIL_SEND,
        ActionType.APPROVE_INVOICE: ToolName.ERP_APPROVE_INVOICE,
        ActionType.CREATE_APPROVAL_PACKET: ToolName.WORKFLOW_CREATE_APPROVAL_PACKET,
        ActionType.CREATE_REDACTED_REPORT: ToolName.REPORTS_CREATE_REDACTED_REPORT,
    }

    default_destination = {
        ActionType.SUMMARIZE_CONTRACT: DestinationType.INTERNAL_UI,
        ActionType.SEND_EMAIL: DestinationType.EXTERNAL_DOMAIN,
        ActionType.APPROVE_INVOICE: DestinationType.ERP_INTERNAL,
        ActionType.CREATE_APPROVAL_PACKET: DestinationType.MANAGER_QUEUE,
        ActionType.CREATE_REDACTED_REPORT: DestinationType.INTERNAL_HR_DASHBOARD,
    }

    data_classes: list[DataClass] = [DataClass.CONTRACT_TERMS]

    if pii_detected:
        data_classes = [DataClass.EMPLOYEE_PII, DataClass.SALARY_DATA]

    if credential_detected:
        data_classes = [DataClass.CREDENTIAL, DataClass.SECRET]

    if action_type == ActionType.APPROVE_INVOICE:
        data_classes = [DataClass.VENDOR_BANK_DETAILS, DataClass.CONTRACT_TERMS]

    if action_type == ActionType.CREATE_REDACTED_REPORT:
        data_classes = [DataClass.EMPLOYEE_PII, DataClass.SALARY_DATA, DataClass.SSN]

    risk_signals: list[RiskSignal] = []

    if pii_detected:
        risk_signals.append(RiskSignal.PII_DETECTED)

    if credential_detected:
        risk_signals.append(RiskSignal.CREDENTIAL_DETECTED)

    if action_type == ActionType.APPROVE_INVOICE:
        risk_signals.append(RiskSignal.FINANCIAL_ACTION)

        if amount_usd is not None and amount_usd > actor.approval_limit_usd:
            risk_signals.append(RiskSignal.HIGH_VALUE_TRANSACTION)

    destination = (
        DestinationType.EXTERNAL_DOMAIN
        if external_destination
        else default_destination[action_type]
    )

    recipient = (
        "external@example.com"
        if destination == DestinationType.EXTERNAL_DOMAIN
        else None
    )

    declared_intent = (
        "Safe internal summary."
        if declared_safe
        else f"User requested {action_type.value}."
    )

    detected_intent = (
        "Potential exfiltration or unsafe execution."
        if external_destination or pii_detected or credential_detected
        else declared_intent
    )

    return ActionScript(
        action_id="sandbox_action",
        actor=actor,
        declared_intent=declared_intent,
        detected_intent=detected_intent,
        action_type=action_type,
        tool_name=tool_by_action[action_type],
        resource_id="sandbox_resource",
        amount_usd=amount_usd,
        destination=destination,
        recipient=recipient,
        data_classes=data_classes,
        risk_signals=risk_signals,
        justification="Interactive sandbox-generated ActionScript.",
    )


st.set_page_config(
    page_title="AxiomGuard AxiomLNN Trace",
    page_icon="🧠",
    layout="wide",
)

st.title("🧠 AxiomLNN Trace")
st.caption(
    "Formula-level explanation of how AxiomGuard turns agent intent and risk metadata into enforceable governance decisions."
)

st.markdown(
    """
    AxiomLNN is the symbolic governance layer. It converts structured agent intent
    and Lobster Trap metadata into truth-bound policy decisions such as:

    ```text
    Allow(x), Deny(x), HumanReview(x), Quarantine(x)
    ```

    The key advantage is not only classification. AxiomGuard can detect **logic paradoxes**:
    the planner may claim an action is safe while inspection metadata indicates exfiltration,
    prompt injection, PII, or excessive agency.
    """
)

gate = DeterministicGate()

st.markdown("---")
st.markdown("## Scenario Trace Viewer")

scenarios = load_redteam_scenarios("data/redteam/attacks.json")

selected = st.selectbox(
    "Select red-team scenario",
    scenarios,
    format_func=lambda scenario: f"{scenario.id} — {scenario.name}",
)

action, findings = build_action_and_findings_for_scenario(selected)
inference = verify_action(action, findings)
decision = gate.enforce(action=action, trap=findings, inference=inference)

render_decision_banner(decision.decision.value)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Matched Policy", decision.matched_policy)
col2.metric("Contradiction Loss", f"{inference.contradiction_loss:.2f}")
col3.metric("Lobster Trap Risk", findings.risk_score)
col4.metric("Tool", action.tool_name.value)

with st.expander("Decision Reason", expanded=True):
    st.write(decision.reason)

if decision.safe_alternative:
    with st.expander("Safe Alternative", expanded=True):
        st.write(decision.safe_alternative)

tab1, tab2, tab3 = st.tabs(
    [
        "ActionScript",
        "Lobster Trap Finding",
        "AxiomLNN Formula Trace",
    ]
)

with tab1:
    st.json(action.model_dump(mode="json"))

with tab2:
    st.json(findings.model_dump(mode="json"))

with tab3:
    render_lnn_trace(inference)


st.markdown("---")
st.markdown("## AxiomLNN Logic Paradox Sandbox")

st.caption(
    "Interactively stress-test what happens when neural intent and perimeter inspection disagree."
)

st.info(
    """
    Demo idea:
    Set **Gemini claims safe summary** to true, then raise the Lobster Trap risk
    or enable exfiltration/prompt injection. Watch contradiction loss rise and the
    deterministic gate fail closed.
    """
)

sandbox_col1, sandbox_col2, sandbox_col3 = st.columns(3)

with sandbox_col1:
    declared_safe = st.checkbox("Gemini claims safe summary", value=True)
    action_kind = st.selectbox(
        "Proposed action type",
        [
            "summarize_contract",
            "send_email",
            "approve_invoice",
            "create_approval_packet",
            "create_redacted_report",
        ],
        index=0,
    )
    actor_role = st.selectbox(
        "Actor role",
        [
            "procurement_analyst",
            "finance_analyst",
            "finance_manager",
            "hr_analyst",
            "ops_analyst",
        ],
        index=0,
    )

with sandbox_col2:
    trap_risk = st.slider("Lobster Trap threat score", 0, 100, 85)
    prompt_injection = st.checkbox("Prompt injection detected", value=False)
    exfiltration = st.checkbox("Exfiltration pattern detected", value=True)
    intent_mismatch = st.checkbox("Declared-vs-detected intent mismatch", value=True)

with sandbox_col3:
    pii_detected = st.checkbox("PII detected", value=True)
    credential_detected = st.checkbox("Credential detected", value=False)
    risky_command = st.checkbox("Risky command detected", value=False)
    external_destination = st.checkbox("External destination", value=False)

approval_limit = 10_000.0
amount_usd = 52_000.0 if action_kind == "approve_invoice" else None

sandbox_actor = ActorProfile(
    id="sandbox_user",
    role=actor_role,
    department="sandbox",
    approval_limit_usd=approval_limit,
)

sandbox_action = _build_sandbox_action(
    actor=sandbox_actor,
    declared_safe=declared_safe,
    action_kind=action_kind,
    external_destination=external_destination,
    pii_detected=pii_detected,
    credential_detected=credential_detected,
    amount_usd=amount_usd,
)

sandbox_finding = LobsterTrapFinding(
    prompt_injection=prompt_injection,
    exfiltration_detected=exfiltration,
    pii_detected=pii_detected,
    credential_detected=credential_detected,
    risky_command_detected=risky_command,
    intent_mismatch=intent_mismatch,
    risk_score=float(trap_risk),
    detected_domains=["attacker@example.com"] if exfiltration else [],
    declared_intent_category="summary" if declared_safe else "workflow",
    detected_intent_category=(
        "data_exfiltration"
        if exfiltration
        else "credential_access"
        if credential_detected
        else "risky_command"
        if risky_command
        else "summary"
    ),
    raw={"source": "axiomlnn_logic_paradox_sandbox"},
)

sandbox_inference = verify_action(sandbox_action, sandbox_finding)
sandbox_decision = gate.enforce(
    action=sandbox_action,
    trap=sandbox_finding,
    inference=sandbox_inference,
)

st.markdown("### Sandbox Result")

render_decision_banner(sandbox_decision.decision.value)

result_col1, result_col2, result_col3, result_col4, result_col5 = st.columns(5)

result_col1.metric("Gate Decision", sandbox_decision.decision.value)
result_col2.metric("Matched Policy", sandbox_decision.matched_policy)
result_col3.metric("Contradiction Loss", f"{sandbox_inference.contradiction_loss:.2f}")
result_col4.metric("Risk Score", sandbox_finding.risk_score)
result_col5.metric("Allow Lower Bound", f"{sandbox_inference.allow.lower:.2f}")

if sandbox_inference.contradiction_loss > 0:
    st.warning(
        "Logic paradox detected: the planner's declared intent and policy/risk signals conflict."
    )

if sandbox_decision.decision.value in {"QUARANTINE", "DENY", "HUMAN_REVIEW"}:
    st.error("AxiomGuard fails closed. Tool execution is not authorized.")
else:
    st.success("AxiomGuard allows execution under the current sandbox configuration.")

with st.expander("Why this matters", expanded=True):
    st.markdown(
        """
        A prompt guardrail might only say **risk is high**.

        AxiomGuard does more:

        ```text
        1. Converts intent into structured facts.
        2. Applies AxiomLNN policy formulas.
        3. Computes truth bounds for decision nodes.
        4. Measures contradiction loss.
        5. Sends the final decision to a deterministic gate.
        6. Blocks tool execution unless the final receipt is ALLOW.
        ```

        This is the enterprise difference: **the model proposes, but the control plane governs**.
        """
    )

sandbox_tab1, sandbox_tab2, sandbox_tab3, sandbox_tab4 = st.tabs(
    [
        "Sandbox ActionScript",
        "Sandbox Lobster Trap",
        "Sandbox AxiomLNN Trace",
        "Formula Score Table",
    ]
)

with sandbox_tab1:
    st.json(sandbox_action.model_dump(mode="json"))

with sandbox_tab2:
    st.json(sandbox_finding.model_dump(mode="json"))

with sandbox_tab3:
    render_lnn_trace(sandbox_inference)

with sandbox_tab4:
    rows = [
        {
            "Policy": formula.policy_id,
            "Decision": formula.decision.value,
            "Score": formula.score,
            "Formula": formula.formula,
            "Trace": formula.trace,
        }
        for formula in sandbox_inference.matched_formulas
    ]

    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.info("No formula matched above zero confidence.")