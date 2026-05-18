from datetime import datetime, timezone
from pathlib import Path

import pytest

from axiomguard_core.receipts import (
    assert_receipt_allows_execution,
    compute_receipt_hash,
    export_receipt_markdown,
    generate_decision_receipt,
    load_receipt_json,
    receipt_to_json,
    save_receipt_json,
    save_receipt_markdown,
    verify_receipt_hash,
)
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

def make_actor() -> ActorProfile:
    return ActorProfile(
        id="user_204",
        role="finance_analyst",
        department="procurement",
        approval_limit_usd=10000,
    )

def make_safe_action() -> ActionScript:
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
        justification="Read-only internal summary.",
    )

def make_high_value_action() -> ActionScript:
    return ActionScript(
        action_id="action_invoice_8821",
        actor=make_actor(),
        declared_intent="Approve high-value invoice.",
        detected_intent="Approve high-value invoice.",
        action_type=ActionType.APPROVE_INVOICE,
        tool_name=ToolName.ERP_APPROVE_INVOICE,
        resource_id="invoice_8821",
        amount_usd=52000,
        destination=DestinationType.ERP_INTERNAL,
        data_classes=[DataClass.VENDOR_BANK_DETAILS, DataClass.CONTRACT_TERMS],
        justification="Invoice appears to match vendor contract.",
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
                trace="Safe read-only internal summary is allowed.",
            )
        ],
        trace="AxiomLNN inferred Allow(action_summary_001).",
    )

def make_human_review_inference() -> AxiomLNNInference:
    return AxiomLNNInference(
        allow=TruthBound(lower=0.0, upper=0.05),
        human_review=TruthBound(lower=0.97, upper=1.0),
        contradiction_loss=0.02,
        matched_formulas=[
            MatchedFormula(
                policy_id="FIN-001",
                decision=Decision.HUMAN_REVIEW,
                formula="ApproveInvoice(x) AND AmountAboveActorLimit(x) -> HumanReview(x)",
                score=0.97,
                trace="High-value invoice approval requires human review.",
            )
        ],
        trace="AxiomLNN inferred HumanReview(action_invoice_8821).",
    )

def test_generate_receipt_attaches_hash_and_preserves_decision():
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-ALLOW-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_safe_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        lnn_inference=make_allow_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.ALLOW,
            reason="Safe internal summary.",
            matched_policy="PROC-004",
            execution_status=ExecutionStatus.NOT_EXECUTED,
        ),
    )

    assert receipt.receipt_id == "AXG-TEST-ALLOW-001"
    assert receipt.receipt_hash is not None
    assert receipt.receipt_hash.startswith("sha256:")
    assert receipt.final_decision == Decision.ALLOW
    assert receipt.allowed_to_execute is True
    assert verify_receipt_hash(receipt) is True

def test_hash_is_stable_for_unchanged_receipt():
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-STABLE-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_safe_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        lnn_inference=make_allow_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.ALLOW,
            reason="Safe internal summary.",
            matched_policy="PROC-004",
            execution_status=ExecutionStatus.NOT_EXECUTED,
        ),
    )

    assert compute_receipt_hash(receipt) == receipt.receipt_hash
    assert verify_receipt_hash(receipt) is True

def test_hash_verification_detects_tampering():
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-TAMPER-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_high_value_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=61),
        lnn_inference=make_human_review_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.HUMAN_REVIEW,
            reason="Invoice exceeds approval limit.",
            matched_policy="FIN-001",
            safe_alternative="Route to finance manager.",
            execution_status=ExecutionStatus.BLOCKED_PENDING_REVIEW,
        ),
    )

    tampered_enforcement = receipt.enforcement.model_copy(
        update={"reason": "Tampered reason."}
    )
    tampered_receipt = receipt.model_copy(
        update={"enforcement": tampered_enforcement}
    )

    assert verify_receipt_hash(receipt) is True
    assert verify_receipt_hash(tampered_receipt) is False

def test_receipt_can_be_saved_and_loaded(tmp_path: Path):
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-SAVE-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_high_value_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=61),
        lnn_inference=make_human_review_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.HUMAN_REVIEW,
            reason="Invoice exceeds approval limit.",
            matched_policy="FIN-001",
            safe_alternative="Route to finance manager.",
            execution_status=ExecutionStatus.BLOCKED_PENDING_REVIEW,
        ),
    )

    path = save_receipt_json(receipt, directory=tmp_path)
    loaded = load_receipt_json(path)

    assert path.exists()
    assert loaded.receipt_id == receipt.receipt_id
    assert loaded.receipt_hash == receipt.receipt_hash
    assert verify_receipt_hash(loaded) is True

def test_receipt_json_contains_expected_fields():
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-JSON-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_safe_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        lnn_inference=make_allow_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.ALLOW,
            reason="Safe internal summary.",
            matched_policy="PROC-004",
            execution_status=ExecutionStatus.NOT_EXECUTED,
        ),
    )

    json_text = receipt_to_json(receipt)

    assert "AXG-TEST-JSON-001" in json_text
    assert "PROC-004" in json_text
    assert "sha256:" in json_text
    assert "summarize_invoice" in json_text

def test_markdown_export_is_ciso_readable():
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-MD-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_high_value_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=61),
        lnn_inference=make_human_review_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.HUMAN_REVIEW,
            reason="Invoice exceeds approval limit.",
            matched_policy="FIN-001",
            safe_alternative="Create approval packet and route to finance manager.",
            execution_status=ExecutionStatus.BLOCKED_PENDING_REVIEW,
        ),
    )

    markdown = export_receipt_markdown(receipt)

    assert "# Decision Receipt: AXG-TEST-MD-001" in markdown
    assert "**Decision:** `HUMAN_REVIEW`" in markdown
    assert "`FIN-001`" in markdown
    assert "Create approval packet" in markdown
    assert "AxiomLNN Inference" in markdown
    assert "Lobster Trap Findings" in markdown
    assert "Receipt hash" in markdown

def test_markdown_can_be_saved(tmp_path: Path):
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-MD-SAVE-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_safe_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        lnn_inference=make_allow_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.ALLOW,
            reason="Safe internal summary.",
            matched_policy="PROC-004",
            execution_status=ExecutionStatus.NOT_EXECUTED,
        ),
    )

    path = save_receipt_markdown(receipt, directory=tmp_path)

    assert path.exists()
    assert path.suffix == ".md"
    assert "Decision Receipt" in path.read_text(encoding="utf-8")

def test_non_allow_receipt_does_not_authorize_execution():
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-BLOCK-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_high_value_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=61),
        lnn_inference=make_human_review_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.HUMAN_REVIEW,
            reason="Invoice exceeds approval limit.",
            matched_policy="FIN-001",
            safe_alternative="Route to finance manager.",
            execution_status=ExecutionStatus.BLOCKED_PENDING_REVIEW,
        ),
    )

    with pytest.raises(PermissionError):
        assert_receipt_allows_execution(receipt)

def test_allow_receipt_authorizes_execution():
    receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-EXEC-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_safe_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        lnn_inference=make_allow_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.ALLOW,
            reason="Safe internal summary.",
            matched_policy="PROC-004",
            execution_status=ExecutionStatus.NOT_EXECUTED,
        ),
    )

    assert_receipt_allows_execution(receipt)

def test_previous_receipt_hash_is_preserved_for_audit_chain():
    first_receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-CHAIN-001",
        timestamp=datetime(2026, 5, 18, tzinfo=timezone.utc),
        action=make_safe_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        lnn_inference=make_allow_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.ALLOW,
            reason="Safe internal summary.",
            matched_policy="PROC-004",
            execution_status=ExecutionStatus.NOT_EXECUTED,
        ),
    )

    second_receipt = generate_decision_receipt(
        receipt_id="AXG-TEST-CHAIN-002",
        timestamp=datetime(2026, 5, 18, 0, 1, tzinfo=timezone.utc),
        action=make_high_value_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=61),
        lnn_inference=make_human_review_inference(),
        enforcement=EnforcementDecision(
            decision=Decision.HUMAN_REVIEW,
            reason="Invoice exceeds approval limit.",
            matched_policy="FIN-001",
            safe_alternative="Route to finance manager.",
            execution_status=ExecutionStatus.BLOCKED_PENDING_REVIEW,
        ),
        previous_receipt_hash=first_receipt.receipt_hash,
    )

    assert second_receipt.previous_receipt_hash == first_receipt.receipt_hash
    assert verify_receipt_hash(second_receipt) is True