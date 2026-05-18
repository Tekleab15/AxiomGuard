from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    ActorProfile,
    DataClass,
    Decision,
    DestinationType,
    LobsterTrapFinding,
    RiskSignal,
    ToolName,
)
from axiomguard_core.verifier import (
    AxiomLNNVerifier,
    IBMLNNAdapterStatus,
    extract_action_facts,
    verify_action,
)

# -------------------------------
# Helpers
# --------------------------------

def make_actor(
    role: str = "finance_analyst",
    approval_limit_usd: float = 10000,
) -> ActorProfile:
    return ActorProfile(
        id="user_204",
        role=role,
        department="procurement",
        approval_limit_usd=approval_limit_usd,
    )

def make_safe_summary_action() -> ActionScript:
    return ActionScript(
        action_id="action_summary_001",
        actor=make_actor(role="procurement_analyst"),
        declared_intent="Summarize invoice for internal review.",
        detected_intent="Summarize invoice for internal review.",
        action_type=ActionType.SUMMARIZE_INVOICE,
        tool_name=ToolName.DOCS_SUMMARIZE,
        resource_id="invoice_101",
        destination=DestinationType.INTERNAL_UI,
        data_classes=[DataClass.VENDOR_NAME, DataClass.CONTRACT_TERMS],
    )

def make_prompt_injected_summary_action() -> ActionScript:
    return ActionScript(
        action_id="action_injected_001",
        actor=make_actor(role="procurement_analyst"),
        declared_intent="Summarize contract.",
        detected_intent="Summarize contract.",
        action_type=ActionType.SUMMARIZE_CONTRACT,
        tool_name=ToolName.DOCS_SUMMARIZE,
        resource_id="contract_injected",
        destination=DestinationType.INTERNAL_UI,
        data_classes=[DataClass.CONTRACT_TERMS],
        risk_signals=[RiskSignal.PROMPT_INJECTION],
    )

def make_high_value_invoice_action() -> ActionScript:
    return ActionScript(
        action_id="action_invoice_8821",
        actor=make_actor(role="finance_analyst", approval_limit_usd=10000),
        declared_intent="Approve high-value invoice.",
        detected_intent="Approve high-value invoice.",
        action_type=ActionType.APPROVE_INVOICE,
        tool_name=ToolName.ERP_APPROVE_INVOICE,
        resource_id="invoice_8821",
        amount_usd=52000,
        destination=DestinationType.ERP_INTERNAL,
        data_classes=[DataClass.VENDOR_BANK_DETAILS, DataClass.CONTRACT_TERMS],
    )

def make_external_pii_email_action() -> ActionScript:
    return ActionScript(
        action_id="action_email_pii_001",
        actor=make_actor(role="hr_analyst"),
        declared_intent="Send employee salary records.",
        detected_intent="External transfer of employee PII.",
        action_type=ActionType.SEND_EMAIL,
        tool_name=ToolName.EMAIL_SEND,
        resource_id="employee_records",
        destination=DestinationType.EXTERNAL_DOMAIN,
        recipient="personal@gmail.com",
        data_classes=[DataClass.EMPLOYEE_PII, DataClass.SALARY_DATA],
    )

def make_safe_external_email_action() -> ActionScript:
    return ActionScript(
        action_id="action_email_safe_001",
        actor=make_actor(role="procurement_manager"),
        declared_intent="Send vendor meeting update.",
        detected_intent="Send vendor meeting update.",
        action_type=ActionType.SEND_EMAIL,
        tool_name=ToolName.EMAIL_SEND,
        resource_id="vendor_update_101",
        destination=DestinationType.EXTERNAL_DOMAIN,
        recipient="vendor@example.com",
        data_classes=[DataClass.CONTRACT_TERMS],
    )

def make_approval_packet_action() -> ActionScript:
    return ActionScript(
        action_id="action_packet_001",
        actor=make_actor(role="finance_analyst"),
        declared_intent="Create approval packet.",
        detected_intent="Create approval packet for manager review.",
        action_type=ActionType.CREATE_APPROVAL_PACKET,
        tool_name=ToolName.WORKFLOW_CREATE_APPROVAL_PACKET,
        resource_id="invoice_8821",
        destination=DestinationType.MANAGER_QUEUE,
        data_classes=[DataClass.VENDOR_BANK_DETAILS, DataClass.CONTRACT_TERMS],
    )

def make_redacted_report_action() -> ActionScript:
    return ActionScript(
        action_id="action_report_001",
        actor=make_actor(role="hr_analyst"),
        declared_intent="Create redacted HR report.",
        detected_intent="Create redacted HR report.",
        action_type=ActionType.CREATE_REDACTED_REPORT,
        tool_name=ToolName.REPORTS_CREATE_REDACTED_REPORT,
        resource_id="employee_records",
        destination=DestinationType.INTERNAL_HR_DASHBOARD,
        data_classes=[DataClass.EMPLOYEE_PII, DataClass.SALARY_DATA, DataClass.SSN],
    )

# -------------------------------------------
# Fact extraction tests
# -------------------------------------------

def test_extract_facts_for_high_value_invoice():
    action = make_high_value_invoice_action()
    trap = LobsterTrapFinding(risk_score=12)

    facts = extract_action_facts(action, trap)

    assert facts["ApproveInvoice"] is True
    assert facts["AmountAboveActorLimit"] is True
    assert facts["ContainsSensitiveData"] is True
    assert facts["InternalDestination"] is True
    assert facts["ExternalDestination"] is False

def test_extract_facts_for_prompt_injection_from_trap_and_action_signal():
    action = make_prompt_injected_summary_action()
    trap = LobsterTrapFinding(prompt_injection=True, risk_score=80)

    facts = extract_action_facts(action, trap)

    assert facts["PromptInjection"] is True
    assert facts["LobsterTrapRiskAtLeast75"] is True
    assert facts["LobsterTrapRiskAtLeast90"] is False

# --------------------------------------
# Policy inference tests
# --------------------------------------

def test_safe_internal_summary_infers_allow():
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=12)

    inference = verify_action(action, trap)

    assert inference.allow.lower >= 0.90
    assert inference.deny.lower == 0.0
    assert inference.quarantine.lower == 0.0
    assert inference.human_review.lower == 0.0
    assert inference.contradiction_loss == 0.0

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "PROC-004" in matched

def test_prompt_injection_infers_quarantine_even_for_read_only_summary():
    action = make_prompt_injected_summary_action()
    trap = LobsterTrapFinding(prompt_injection=True, risk_score=20)

    inference = verify_action(action, trap)

    assert inference.quarantine.lower >= 0.90
    assert inference.allow.lower >= 0.90
    assert inference.contradiction_loss > 0.0

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "SEC-003" in matched
    assert "PROC-004" in matched

def test_high_lobstertrap_risk_infers_quarantine():
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=94)

    inference = verify_action(action, trap)

    assert inference.quarantine.lower >= 0.90

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "SEC-004" in matched

def test_external_sensitive_email_infers_deny():
    action = make_external_pii_email_action()
    trap = LobsterTrapFinding(risk_score=20, pii_detected=True)

    inference = verify_action(action, trap)

    assert inference.deny.lower >= 0.90
    assert inference.allow.lower == 0.0

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "DATA-002" in matched

def test_credential_detection_infers_deny():
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=20, credential_detected=True)

    inference = verify_action(action, trap)

    assert inference.deny.lower >= 0.90

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "DATA-003" in matched

def test_risky_command_detection_infers_deny():
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=20, risky_command_detected=True)

    inference = verify_action(action, trap)

    assert inference.deny.lower >= 0.90

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "SEC-005" in matched

def test_high_value_invoice_infers_human_review():
    action = make_high_value_invoice_action()
    trap = LobsterTrapFinding(risk_score=12)

    inference = verify_action(action, trap)

    assert inference.human_review.lower >= 0.90
    assert inference.allow.lower == 0.0

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "FIN-001" in matched
    assert "AmountAboveActorLimit" in inference.trace

def test_intent_mismatch_infers_human_review():
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(
        risk_score=30,
        intent_mismatch=True,
        declared_intent_category="summary",
        detected_intent_category="data_exfiltration",
    )

    inference = verify_action(action, trap)

    assert inference.human_review.lower >= 0.90
    assert inference.contradiction_loss > 0.0

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "INTENT-001" in matched
    assert "PROC-004" in matched

def test_elevated_risk_infers_human_review():
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=76)

    inference = verify_action(action, trap)

    assert inference.human_review.lower >= 0.90

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "RISK-001" in matched

def test_safe_approval_packet_infers_allow():
    action = make_approval_packet_action()
    trap = LobsterTrapFinding(risk_score=25)

    inference = verify_action(action, trap)

    assert inference.allow.lower >= 0.90

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "WORKFLOW-001" in matched

def test_safe_redacted_report_infers_allow():
    action = make_redacted_report_action()
    trap = LobsterTrapFinding(risk_score=25, pii_detected=True)

    inference = verify_action(action, trap)

    assert inference.allow.lower >= 0.90
    assert inference.deny.lower == 0.0

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "REPORT-001" in matched

def test_safe_non_sensitive_external_email_infers_allow():
    action = make_safe_external_email_action()
    trap = LobsterTrapFinding(risk_score=20)

    inference = verify_action(action, trap)

    assert inference.allow.lower >= 0.80
    assert inference.deny.lower == 0.0

    matched = {formula.policy_id for formula in inference.matched_formulas}
    assert "COMM-001" in matched

def test_trace_contains_decision_scores_and_matched_formula():
    action = make_high_value_invoice_action()
    trap = LobsterTrapFinding(risk_score=12)

    inference = verify_action(action, trap)

    assert "AxiomLNN Verification Trace" in inference.trace
    assert "FIN-001" in inference.trace
    assert "HumanReview" in inference.trace
    assert "Decision Node Scores" in inference.trace
    assert "Contradiction Loss" in inference.trace

def test_ibm_lnn_adapter_status_is_safe_to_call():
    # This test should pass whether IBM LNN is installed or not.
    available = IBMLNNAdapterStatus.is_available()

    assert isinstance(available, bool)

    if not available:
        assert "pip install git+https://github.com/IBM/LNN" in (
            IBMLNNAdapterStatus.import_error_message()
        )