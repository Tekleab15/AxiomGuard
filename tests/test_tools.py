from datetime import datetime, timezone

import pytest

from axiomguard_core.receipts import generate_decision_receipt
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
    MatchedFormula,
    ToolName,
    TruthBound,
)
from axiomguard_core.tools import (
    attempt_tool_execution,
    execute_authorized_tool,
    get_supported_tool_names,
    infer_redactions,
    is_tool_action_compatible,
)

# --------------------------------
# Test helpers
# --------------------------------

def make_actor(
    role: str = "procurement_analyst",
    approval_limit_usd: float = 10000,
) -> ActorProfile:
    return ActorProfile(
        id="user_204",
        role=role,
        department="procurement",
        approval_limit_usd=approval_limit_usd,
    )

def make_allow_inference() -> AxiomLNNInference:
    return AxiomLNNInference(
        allow=TruthBound.point(0.92),
        matched_formulas=[
            MatchedFormula(
                policy_id="PROC-004",
                decision=Decision.ALLOW,
                formula="SummarizeDocument(x) AND InternalDestination(x) -> Allow(x)",
                score=0.92,
                trace="Safe internal action is allowed.",
            )
        ],
    )

def make_human_review_inference() -> AxiomLNNInference:
    return AxiomLNNInference(
        human_review=TruthBound.point(0.97),
        matched_formulas=[
            MatchedFormula(
                policy_id="FIN-001",
                decision=Decision.HUMAN_REVIEW,
                formula="ApproveInvoice(x) AND AmountAboveActorLimit(x) -> HumanReview(x)",
                score=0.97,
                trace="High-value invoice requires human review.",
            )
        ],
    )

def make_allow_receipt(action: ActionScript, receipt_id: str = "AXG-TOOL-ALLOW") :
    return generate_decision_receipt(
        receipt_id=receipt_id,
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=action,
        lobstertrap_findings=LobsterTrapFinding(risk_score=10),
        lnn_inference=make_allow_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.ALLOW,
            reason="Action is allowed by policy.",
            matched_policy="ALLOW-TEST",
            execution_status=ExecutionStatus.NOT_EXECUTED,
        ),
    )

def make_blocked_receipt(action: ActionScript, receipt_id: str = "AXG-TOOL-BLOCK"):
    return generate_decision_receipt(
        receipt_id=receipt_id,
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=action,
        lobstertrap_findings=LobsterTrapFinding(risk_score=61),
        lnn_inference=make_human_review_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.HUMAN_REVIEW,
            reason="Action requires human review.",
            matched_policy="FIN-001",
            safe_alternative="Create approval packet and route to finance manager.",
            execution_status=ExecutionStatus.BLOCKED_PENDING_REVIEW,
        ),
    )

def make_summary_action() -> ActionScript:
    return ActionScript(
        action_id="action_summary_001",
        actor=make_actor(),
        declared_intent="Summarize invoice for internal review.",
        detected_intent="Summarize invoice for internal review.",
        action_type=ActionType.SUMMARIZE_INVOICE,
        tool_name=ToolName.DOCS_SUMMARIZE,
        resource_id="invoice_101",
        destination=DestinationType.INTERNAL_UI,
        data_classes=[DataClass.VENDOR_NAME, DataClass.CONTRACT_TERMS],
    )

def make_invoice_approval_action() -> ActionScript:
    return ActionScript(
        action_id="action_approval_001",
        actor=make_actor(role="finance_manager", approval_limit_usd=100000),
        declared_intent="Approve invoice.",
        detected_intent="Approve invoice.",
        action_type=ActionType.APPROVE_INVOICE,
        tool_name=ToolName.ERP_APPROVE_INVOICE,
        resource_id="invoice_202",
        amount_usd=5000,
        destination=DestinationType.ERP_INTERNAL,
        data_classes=[DataClass.CONTRACT_TERMS],
    )

def make_safe_email_action() -> ActionScript:
    return ActionScript(
        action_id="action_email_001",
        actor=make_actor(role="procurement_manager"),
        declared_intent="Send vendor status update.",
        detected_intent="Send non-sensitive vendor status update.",
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
        detected_intent="Create redacted internal HR report.",
        action_type=ActionType.CREATE_REDACTED_REPORT,
        tool_name=ToolName.REPORTS_CREATE_REDACTED_REPORT,
        resource_id="employee_records",
        destination=DestinationType.INTERNAL_HR_DASHBOARD,
        data_classes=[
            DataClass.EMPLOYEE_PII,
            DataClass.SALARY_DATA,
            DataClass.SSN,
        ],
    )

def make_tool_mismatch_action() -> ActionScript:
    return ActionScript(
        action_id="action_mismatch_001",
        actor=make_actor(role="finance_manager", approval_limit_usd=100000),
        declared_intent="Approve invoice.",
        detected_intent="Approve invoice.",
        action_type=ActionType.APPROVE_INVOICE,
        tool_name=ToolName.EMAIL_SEND,
        resource_id="invoice_999",
        amount_usd=100,
        destination=DestinationType.ERP_INTERNAL,
        data_classes=[DataClass.CONTRACT_TERMS],
    )

# ------------------------------------
# Tests
# ------------------------------------

def test_supported_tool_names_are_available():
    supported = get_supported_tool_names()

    assert ToolName.DOCS_SUMMARIZE.value in supported
    assert ToolName.ERP_APPROVE_INVOICE.value in supported
    assert ToolName.EMAIL_SEND.value in supported
    assert ToolName.WORKFLOW_CREATE_APPROVAL_PACKET.value in supported
    assert ToolName.REPORTS_CREATE_REDACTED_REPORT.value in supported

def test_tool_action_compatibility_matrix():
    assert is_tool_action_compatible(
        ToolName.DOCS_SUMMARIZE,
        ActionType.SUMMARIZE_INVOICE,
    )

    assert is_tool_action_compatible(
        ToolName.ERP_APPROVE_INVOICE,
        ActionType.APPROVE_INVOICE,
    )

    assert not is_tool_action_compatible(
        ToolName.EMAIL_SEND,
        ActionType.APPROVE_INVOICE,
    )

def test_execute_authorized_document_summary():
    receipt = make_allow_receipt(
        make_summary_action(),
        receipt_id="AXG-TOOL-SUMMARY-001",
    )

    result = execute_authorized_tool(receipt)

    assert result.executed is True
    assert result.tool_name == ToolName.DOCS_SUMMARIZE
    assert result.receipt_id == receipt.receipt_id
    assert result.status == "simulated_execution_complete"
    assert result.output["resource_id"] == "invoice_101"
    assert result.output["external_transfer"] is False
    assert "summary" in result.output

def test_execute_authorized_erp_approval():
    receipt = make_allow_receipt(
        make_invoice_approval_action(),
        receipt_id="AXG-TOOL-ERP-001",
    )

    result = execute_authorized_tool(receipt)

    assert result.executed is True
    assert result.tool_name == ToolName.ERP_APPROVE_INVOICE
    assert result.output["approval_id"] == "SIM-APPROVAL-invoice_202"
    assert result.output["approved_amount_usd"] == 5000
    assert result.output["simulated"] is True

def test_execute_authorized_email_send_is_simulated_only():
    receipt = make_allow_receipt(
        make_safe_email_action(),
        receipt_id="AXG-TOOL-EMAIL-001",
    )

    result = execute_authorized_tool(receipt)

    assert result.executed is True
    assert result.tool_name == ToolName.EMAIL_SEND
    assert result.output["recipient"] == "vendor@example.com"
    assert result.output["delivery_mode"] == "simulated_only"
    assert result.output["simulated"] is True

def test_execute_authorized_approval_packet_creation():
    receipt = make_allow_receipt(
        make_approval_packet_action(),
        receipt_id="AXG-TOOL-PACKET-001",
    )

    result = execute_authorized_tool(receipt)

    assert result.executed is True
    assert result.tool_name == ToolName.WORKFLOW_CREATE_APPROVAL_PACKET
    assert result.output["packet_id"] == "SIM-PACKET-invoice_8821"
    assert result.output["reviewer_role"] == "finance_manager"

def test_execute_authorized_redacted_report_creation():
    receipt = make_allow_receipt(
        make_redacted_report_action(),
        receipt_id="AXG-TOOL-REPORT-001",
    )

    result = execute_authorized_tool(receipt)

    assert result.executed is True
    assert result.tool_name == ToolName.REPORTS_CREATE_REDACTED_REPORT
    assert result.output["report_id"] == "SIM-REPORT-employee_records"
    assert "ssn" in result.output["redactions"]
    assert "salary" in result.output["redactions"]
    assert result.output["data_classes_after_redaction"] == [
        DataClass.AGGREGATED_HR_METRICS.value
    ]

def test_non_allow_receipt_cannot_execute_tool():
    receipt = make_blocked_receipt(
        make_invoice_approval_action(),
        receipt_id="AXG-TOOL-BLOCKED-001",
    )

    with pytest.raises(PermissionError):
        execute_authorized_tool(receipt)

def test_attempt_tool_execution_returns_blocked_result_for_non_allow_receipt():
    receipt = make_blocked_receipt(
        make_invoice_approval_action(),
        receipt_id="AXG-TOOL-BLOCKED-002",
    )

    result = attempt_tool_execution(receipt)

    assert result.executed is False
    assert result.status == "blocked_by_axiomguard"
    assert "does not authorize execution" in result.blocked_reason

def test_tampered_allow_receipt_cannot_execute_tool():
    receipt = make_allow_receipt(
        make_summary_action(),
        receipt_id="AXG-TOOL-TAMPER-001",
    )

    tampered_action = receipt.action.model_copy(
        update={"resource_id": "tampered_invoice"}
    )
    tampered_receipt = receipt.model_copy(
        update={"action": tampered_action}
    )

    with pytest.raises(PermissionError):
        execute_authorized_tool(tampered_receipt)

def test_tool_action_mismatch_is_blocked_even_with_allow_receipt():
    receipt = make_allow_receipt(
        make_tool_mismatch_action(),
        receipt_id="AXG-TOOL-MISMATCH-001",
    )

    with pytest.raises(PermissionError):
        execute_authorized_tool(receipt)

def test_attempt_tool_execution_returns_blocked_result_for_tool_mismatch():
    receipt = make_allow_receipt(
        make_tool_mismatch_action(),
        receipt_id="AXG-TOOL-MISMATCH-002",
    )

    result = attempt_tool_execution(receipt)

    assert result.executed is False
    assert result.status == "blocked_by_axiomguard"
    assert "Tool/action mismatch" in result.blocked_reason

def test_infer_redactions_for_sensitive_hr_data():
    redactions = infer_redactions(
        [
            DataClass.EMPLOYEE_PII,
            DataClass.SALARY_DATA,
            DataClass.SSN,
        ]
    )

    assert "employee_name" in redactions
    assert "salary" in redactions
    assert "ssn" in redactions

def test_infer_redactions_returns_none_required_for_non_sensitive_data():
    redactions = infer_redactions(
        [
            DataClass.CONTRACT_TERMS,
            DataClass.VENDOR_NAME,
        ]
    )

    assert redactions == ["none_required"]