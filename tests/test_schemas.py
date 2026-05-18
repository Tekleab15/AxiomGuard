import pytest

from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    ActorProfile,
    AxiomLNNInference,
    DataClass,
    Decision,
    DestinationType,
    EnforcementDecision,
    ExecutionStatus,
    LobsterTrapFinding,
    ToolName,
    TruthBound,
)


def test_lobstertrap_risk_score_normalizes_from_zero_to_one_scale():
    finding = LobsterTrapFinding(risk_score=0.94)
    assert finding.risk_score == 94.0


def test_lobstertrap_risk_score_accepts_zero_to_hundred_scale():
    finding = LobsterTrapFinding(risk_score=61)
    assert finding.risk_score == 61.0


def test_approve_invoice_requires_amount():
    actor = ActorProfile(
        id="user_204",
        role="finance_analyst",
        department="procurement",
        approval_limit_usd=10000,
    )

    with pytest.raises(ValueError):
        ActionScript(
            action_id="action_001",
            actor=actor,
            declared_intent="Approve invoice",
            action_type=ActionType.APPROVE_INVOICE,
            tool_name=ToolName.ERP_APPROVE_INVOICE,
            destination=DestinationType.ERP_INTERNAL,
        )


def test_send_email_requires_recipient():
    actor = ActorProfile(id="user_204", role="hr_analyst")

    with pytest.raises(ValueError):
        ActionScript(
            action_id="action_002",
            actor=actor,
            declared_intent="Send employee data",
            action_type=ActionType.SEND_EMAIL,
            tool_name=ToolName.EMAIL_SEND,
            destination=DestinationType.EXTERNAL_DOMAIN,
            data_classes=[DataClass.EMPLOYEE_PII],
        )


def test_sensitive_external_transfer_properties():
    actor = ActorProfile(id="user_204", role="hr_analyst")

    action = ActionScript(
        action_id="action_003",
        actor=actor,
        declared_intent="Send employee salary data",
        action_type=ActionType.SEND_EMAIL,
        tool_name=ToolName.EMAIL_SEND,
        destination=DestinationType.EXTERNAL_DOMAIN,
        recipient="personal@gmail.com",
        data_classes=[DataClass.EMPLOYEE_PII, DataClass.SALARY_DATA],
    )

    assert action.touches_sensitive_data is True
    assert action.is_external_transfer is True


def test_high_value_transaction_property():
    actor = ActorProfile(
        id="user_204",
        role="finance_analyst",
        approval_limit_usd=10000,
    )

    action = ActionScript(
        action_id="action_004",
        actor=actor,
        declared_intent="Approve high-value invoice",
        action_type=ActionType.APPROVE_INVOICE,
        tool_name=ToolName.ERP_APPROVE_INVOICE,
        amount_usd=52000,
        destination=DestinationType.ERP_INTERNAL,
    )

    assert action.is_high_value_transaction is True


def test_truth_bound_rejects_invalid_interval():
    with pytest.raises(ValueError):
        TruthBound(lower=0.9, upper=0.2)


def test_lnn_score_lookup():
    inference = AxiomLNNInference(
        human_review=TruthBound(lower=0.97, upper=1.0)
    )

    assert inference.score_for(Decision.HUMAN_REVIEW) == 0.97


def test_enforcement_allow_property():
    decision = EnforcementDecision(
        decision=Decision.ALLOW,
        reason="Safe internal summary.",
        matched_policy="PROC-004",
        execution_status=ExecutionStatus.EXECUTED,
    )

    assert decision.allowed_to_execute is True

def test_enforcement_block_property():
    decision = EnforcementDecision(
        decision=Decision.HUMAN_REVIEW,
        reason="Invoice exceeds approval limit.",
        matched_policy="FIN-001",
        execution_status=ExecutionStatus.BLOCKED_PENDING_REVIEW,
    )

    assert decision.allowed_to_execute is False