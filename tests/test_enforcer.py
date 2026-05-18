from axiomguard_core.enforcer import DeterministicGate
from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    ActorProfile,
    AxiomLNNInference,
    DataClass,
    Decision,
    DestinationType,
    ExecutionStatus,
    LobsterTrapFinding,
    MatchedFormula,
    ToolName,
    TruthBound,
)

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

def make_high_value_approval_action() -> ActionScript:
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
        action_id="action_email_001",
        actor=make_actor(role="hr_analyst"),
        declared_intent="Send employee salary data to personal email.",
        detected_intent="External transfer of employee PII.",
        action_type=ActionType.SEND_EMAIL,
        tool_name=ToolName.EMAIL_SEND,
        resource_id="employee_records",
        destination=DestinationType.EXTERNAL_DOMAIN,
        recipient="personal@gmail.com",
        data_classes=[DataClass.EMPLOYEE_PII, DataClass.SALARY_DATA],
    )

def make_tool_mismatch_action() -> ActionScript:
    return ActionScript(
        action_id="action_mismatch_001",
        actor=make_actor(role="finance_analyst"),
        declared_intent="Approve invoice.",
        detected_intent="Approve invoice.",
        action_type=ActionType.APPROVE_INVOICE,
        tool_name=ToolName.EMAIL_SEND,
        resource_id="invoice_777",
        amount_usd=500,
        destination=DestinationType.ERP_INTERNAL,
        data_classes=[DataClass.CONTRACT_TERMS],
    )

def make_inference(
    allow: float = 0.0,
    deny: float = 0.0,
    redact: float = 0.0,
    quarantine: float = 0.0,
    human_review: float = 0.0,
    rate_limit: float = 0.0,
    contradiction_loss: float = 0.0,
) -> AxiomLNNInference:
    matched_formulas = []

    if quarantine > 0:
        matched_formulas.append(
            MatchedFormula(
                policy_id="SEC-003",
                decision=Decision.QUARANTINE,
                formula="PromptInjection(x) OR ExfiltrationDetected(x) -> Quarantine(x)",
                score=quarantine,
                trace="Prompt injection or exfiltration implies quarantine.",
            )
        )

    if deny > 0:
        matched_formulas.append(
            MatchedFormula(
                policy_id="DATA-002",
                decision=Decision.DENY,
                formula="SendEmail(x) AND ContainsSensitiveData(x) AND ExternalDestination(x) -> Deny(x)",
                score=deny,
                trace="Sensitive data cannot be sent externally.",
            )
        )

    if human_review > 0:
        matched_formulas.append(
            MatchedFormula(
                policy_id="FIN-001",
                decision=Decision.HUMAN_REVIEW,
                formula="ApproveInvoice(x) AND AmountAboveActorLimit(x) -> HumanReview(x)",
                score=human_review,
                trace="High-value invoice approval requires human review.",
            )
        )

    if redact > 0:
        matched_formulas.append(
            MatchedFormula(
                policy_id="DATA-004",
                decision=Decision.REDACT,
                formula="ContainsSensitiveData(x) AND InternalReport(x) -> Redact(x)",
                score=redact,
                trace="Sensitive fields must be redacted before reporting.",
            )
        )

    if allow > 0:
        matched_formulas.append(
            MatchedFormula(
                policy_id="PROC-004",
                decision=Decision.ALLOW,
                formula="SummarizeDocument(x) AND InternalDestination(x) -> Allow(x)",
                score=allow,
                trace="Safe read-only internal summary is allowed.",
            )
        )

    return AxiomLNNInference(
        allow=TruthBound.point(allow),
        deny=TruthBound.point(deny),
        redact=TruthBound.point(redact),
        quarantine=TruthBound.point(quarantine),
        human_review=TruthBound.point(human_review),
        rate_limit=TruthBound.point(rate_limit),
        contradiction_loss=contradiction_loss,
        matched_formulas=matched_formulas,
    )

def test_prompt_injection_quarantines_even_if_lnn_allows():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(prompt_injection=True, risk_score=20)
    inference = make_inference(allow=0.95)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.QUARANTINE
    assert decision.matched_policy == "SEC-003"
    assert decision.execution_status == ExecutionStatus.BLOCKED_QUARANTINED
    assert decision.allowed_to_execute is False

def test_high_trap_risk_quarantines():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=94)
    inference = make_inference(allow=0.95)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.QUARANTINE
    assert decision.matched_policy == "SEC-004"
    assert decision.allowed_to_execute is False

def test_external_sensitive_email_is_denied_even_if_lnn_allows():
    gate = DeterministicGate()
    action = make_external_pii_email_action()
    trap = LobsterTrapFinding(risk_score=10)
    inference = make_inference(allow=0.95)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.DENY
    assert decision.matched_policy == "DATA-002"
    assert decision.execution_status == ExecutionStatus.BLOCKED_DENIED
    assert decision.allowed_to_execute is False

def test_high_value_invoice_requires_human_review():
    gate = DeterministicGate()
    action = make_high_value_approval_action()
    trap = LobsterTrapFinding(risk_score=10)
    inference = make_inference(allow=0.90)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.HUMAN_REVIEW
    assert decision.matched_policy == "FIN-001"
    assert decision.execution_status == ExecutionStatus.BLOCKED_PENDING_REVIEW
    assert decision.allowed_to_execute is False

def test_tool_action_mismatch_is_denied():
    gate = DeterministicGate()
    action = make_tool_mismatch_action()
    trap = LobsterTrapFinding(risk_score=5)
    inference = make_inference(allow=0.95)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.DENY
    assert decision.matched_policy == "TOOL-001"
    assert decision.allowed_to_execute is False

def test_safe_internal_summary_is_allowed():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=12)
    inference = make_inference(allow=0.92)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.ALLOW
    assert decision.matched_policy == "PROC-004"
    assert decision.execution_status == ExecutionStatus.NOT_EXECUTED
    assert decision.allowed_to_execute is True

def test_allow_is_blocked_when_trap_risk_is_too_high():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=65)
    inference = make_inference(allow=0.92)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.HUMAN_REVIEW
    assert decision.matched_policy == "DEFAULT-REVIEW"
    assert decision.allowed_to_execute is False

def test_lnn_quarantine_has_priority_over_deny_and_review():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=10)
    inference = make_inference(
        quarantine=0.85,
        deny=0.99,
        human_review=0.99,
        allow=0.99,
    )

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.QUARANTINE
    assert decision.matched_policy == "SEC-003"
    assert decision.allowed_to_execute is False

def test_lnn_deny_has_priority_over_human_review_and_allow():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=10)
    inference = make_inference(
        deny=0.85,
        human_review=0.99,
        allow=0.99,
    )

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.DENY
    assert decision.matched_policy == "DATA-002"
    assert decision.allowed_to_execute is False

def test_human_review_has_priority_over_redact_and_allow():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=10)
    inference = make_inference(
        human_review=0.75,
        redact=0.95,
        allow=0.99,
    )

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.HUMAN_REVIEW
    assert decision.matched_policy == "FIN-001"
    assert decision.allowed_to_execute is False

def test_contradiction_loss_forces_human_review():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=10)
    inference = make_inference(allow=0.95, contradiction_loss=0.40)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.HUMAN_REVIEW
    assert decision.matched_policy == "LNN-001"
    assert decision.allowed_to_execute is False

def test_default_is_human_review_when_no_score_is_sufficient():
    gate = DeterministicGate()
    action = make_safe_summary_action()
    trap = LobsterTrapFinding(risk_score=10)
    inference = make_inference(allow=0.30, deny=0.10, human_review=0.10)

    decision = gate.enforce(action, trap, inference)

    assert decision.decision == Decision.HUMAN_REVIEW
    assert decision.matched_policy == "DEFAULT-REVIEW"
    assert decision.allowed_to_execute is False