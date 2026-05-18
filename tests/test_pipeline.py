from pathlib import Path

from axiomguard_core.pipeline import (
    AxiomGuardPipeline,
    PipelineOptions,
    run_axiomguard_pipeline,
    run_pipeline_no_execution,
)
from axiomguard_core.receipts import load_receipt_json, verify_receipt_hash
from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    ActorProfile,
    DataClass,
    Decision,
    DestinationType,
    LobsterTrapFinding,
    ToolName,
)

# -----------------------------------
# Test helpers
# -----------------------------------

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
        declared_intent="Summarize injected vendor contract.",
        detected_intent="Summarize injected vendor contract.",
        action_type=ActionType.SUMMARIZE_CONTRACT,
        tool_name=ToolName.DOCS_SUMMARIZE,
        resource_id="contract_injected",
        destination=DestinationType.INTERNAL_UI,
        data_classes=[DataClass.CONTRACT_TERMS],
    )

def make_high_value_invoice_action() -> ActionScript:
    return ActionScript(
        action_id="action_invoice_8821",
        actor=make_actor(role="finance_analyst", approval_limit_usd=10000),
        declared_intent="Approve high-value vendor invoice.",
        detected_intent="Approve high-value vendor invoice.",
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
        declared_intent="Send employee salary records to personal email.",
        detected_intent="External transfer of employee PII.",
        action_type=ActionType.SEND_EMAIL,
        tool_name=ToolName.EMAIL_SEND,
        resource_id="employee_records",
        destination=DestinationType.EXTERNAL_DOMAIN,
        recipient="personal@gmail.com",
        data_classes=[DataClass.EMPLOYEE_PII, DataClass.SALARY_DATA],
    )

def make_safe_approval_packet_action() -> ActionScript:
    return ActionScript(
        action_id="action_packet_001",
        actor=make_actor(role="finance_analyst"),
        declared_intent="Create approval packet for finance manager.",
        detected_intent="Create approval packet for finance manager.",
        action_type=ActionType.CREATE_APPROVAL_PACKET,
        tool_name=ToolName.WORKFLOW_CREATE_APPROVAL_PACKET,
        resource_id="invoice_8821",
        destination=DestinationType.MANAGER_QUEUE,
        data_classes=[DataClass.VENDOR_BANK_DETAILS, DataClass.CONTRACT_TERMS],
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


# ------------------------------
# Tests
# ------------------------------
def test_pipeline_deep_copies_action_to_prevent_mutability_leak():
    action = make_safe_summary_action()
    findings = LobsterTrapFinding(risk_score=12)

    result = run_axiomguard_pipeline(
        action=action,
        lobstertrap_findings=findings,
    )

    original_receipt_resource = result.receipt.action.resource_id

    # Mutate the original object after pipeline execution.
    action.resource_id = "malicious_external_resource"

    # The receipt and pipeline result must remain sealed to the original value.
    assert result.action.resource_id == original_receipt_resource
    assert result.receipt.action.resource_id == original_receipt_resource
    assert result.receipt.action.resource_id == "invoice_101"
def test_pipeline_deep_copies_lobstertrap_findings():
    action = make_safe_summary_action()
    findings = LobsterTrapFinding(risk_score=12)

    result = run_axiomguard_pipeline(
        action=action,
        lobstertrap_findings=findings,
    )

    findings.risk_score = 99

    assert result.lobstertrap_findings.risk_score == 12
    assert result.receipt.lobstertrap_findings.risk_score == 12
def test_dashboard_dict_has_explicit_tool_result_for_dry_run():
    result = run_pipeline_no_execution(
        action=make_safe_summary_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
    )

    dashboard = result.to_dashboard_dict()

    assert dashboard["tool_result"] is not None
    assert dashboard["tool_result"]["executed"] is False
    assert dashboard["tool_result"]["status"] == "skipped_dry_run_preview"
    assert dashboard["tool_result"]["receipt_id"] == result.receipt.receipt_id
    assert "Execution skipped" in dashboard["tool_result"]["blocked_reason"]

def test_persistence_failure_does_not_crash_core_pipeline():
    result = run_axiomguard_pipeline(
        action=make_safe_summary_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        options=PipelineOptions(
            persist_receipt=True,
            export_markdown=True,
            receipt_directory="bad\0path",
            execute_tools=True,
        ),
    )

    assert result.final_decision == Decision.ALLOW
    assert result.executed is True
    assert result.persistence_error is not None
    assert "ValueError" in result.persistence_error or "embedded null" in result.persistence_error
    assert result.receipt_json_path is None
    assert result.receipt_markdown_path is None


def test_safe_internal_summary_runs_full_pipeline_and_executes_tool():
    pipeline = AxiomGuardPipeline()

    result = pipeline.run(
        action=make_safe_summary_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
    )

    assert result.final_decision == Decision.ALLOW
    assert result.allowed_to_execute is True
    assert result.executed is True
    assert result.tool_result is not None
    assert result.tool_result.executed is True
    assert result.tool_result.output["resource_id"] == "invoice_101"
    assert result.enforcement.matched_policy == "PROC-004"
    assert verify_receipt_hash(result.receipt) is True

    assert "verify" in result.stage_timings_ms
    assert "enforce" in result.stage_timings_ms
    assert "receipt" in result.stage_timings_ms
    assert "execute" in result.stage_timings_ms
    assert "total" in result.stage_timings_ms

def test_prompt_injection_runs_full_pipeline_and_quarantines():
    result = run_axiomguard_pipeline(
        action=make_prompt_injected_summary_action(),
        lobstertrap_findings=LobsterTrapFinding(
            prompt_injection=True,
            risk_score=20,
            detected_domains=["attacker@example.com"],
        ),
    )

    assert result.final_decision == Decision.QUARANTINE
    assert result.allowed_to_execute is False
    assert result.executed is False
    assert result.tool_result is not None
    assert result.tool_result.status == "blocked_by_axiomguard"
    assert result.enforcement.matched_policy == "SEC-003"
    assert result.lnn_inference.quarantine.lower >= 0.90
    assert verify_receipt_hash(result.receipt) is True

def test_high_value_invoice_runs_full_pipeline_and_routes_to_human_review():
    result = run_axiomguard_pipeline(
        action=make_high_value_invoice_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
    )

    assert result.final_decision == Decision.HUMAN_REVIEW
    assert result.allowed_to_execute is False
    assert result.executed is False
    assert result.enforcement.matched_policy == "FIN-001"
    assert result.lnn_inference.human_review.lower >= 0.90
    assert "approval packet" in result.enforcement.safe_alternative.lower()
    assert result.receipt.enforcement.safe_alternative == result.enforcement.safe_alternative

def test_external_pii_email_runs_full_pipeline_and_denies():
    result = run_axiomguard_pipeline(
        action=make_external_pii_email_action(),
        lobstertrap_findings=LobsterTrapFinding(
            risk_score=25,
            pii_detected=True,
            detected_domains=["personal@gmail.com"],
        ),
    )

    assert result.final_decision == Decision.DENY
    assert result.allowed_to_execute is False
    assert result.executed is False
    assert result.enforcement.matched_policy == "DATA-002"
    assert result.lnn_inference.deny.lower >= 0.90
    assert "external" in result.enforcement.reason.lower()

def test_safe_approval_packet_runs_full_pipeline_and_executes():
    result = run_axiomguard_pipeline(
        action=make_safe_approval_packet_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=20),
    )

    assert result.final_decision == Decision.ALLOW
    assert result.executed is True
    assert result.tool_result is not None
    assert result.tool_result.output["packet_id"] == "SIM-PACKET-invoice_8821"
    assert result.enforcement.matched_policy == "WORKFLOW-001"
    assert result.lnn_inference.allow.lower >= 0.90

def test_tool_mismatch_runs_full_pipeline_and_denies_before_execution():
    result = run_axiomguard_pipeline(
        action=make_tool_mismatch_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=5),
    )

    assert result.final_decision == Decision.DENY
    assert result.enforcement.matched_policy == "TOOL-001"
    assert result.executed is False
    assert result.tool_result is not None
    assert result.tool_result.status == "blocked_by_axiomguard"

def test_pipeline_can_persist_json_and_markdown_receipts(tmp_path: Path):
    result = run_axiomguard_pipeline(
        action=make_high_value_invoice_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        options=PipelineOptions(
            persist_receipt=True,
            export_markdown=True,
            receipt_directory=tmp_path,
        ),
    )

    assert result.receipt_json_path is not None
    assert result.receipt_markdown_path is not None

    json_path = Path(result.receipt_json_path)
    markdown_path = Path(result.receipt_markdown_path)

    assert json_path.exists()
    assert markdown_path.exists()
    assert json_path.suffix == ".json"
    assert markdown_path.suffix == ".md"

    loaded_receipt = load_receipt_json(json_path)

    assert loaded_receipt.receipt_id == result.receipt.receipt_id
    assert verify_receipt_hash(loaded_receipt) is True
    assert "Decision Receipt" in markdown_path.read_text(encoding="utf-8")

def test_pipeline_dry_run_creates_receipt_without_tool_execution():
    result = run_pipeline_no_execution(
        action=make_safe_summary_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
    )

    assert result.final_decision == Decision.ALLOW
    assert result.allowed_to_execute is True
    assert result.tool_result is None
    assert result.executed is False
    assert verify_receipt_hash(result.receipt) is True

def test_pipeline_preserves_previous_receipt_hash_for_audit_chain():
    first = run_axiomguard_pipeline(
        action=make_safe_summary_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
    )

    second = run_axiomguard_pipeline(
        action=make_high_value_invoice_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
        options=PipelineOptions(
            previous_receipt_hash=first.receipt.receipt_hash,
            execute_tools=True,
        ),
    )

    assert second.receipt.previous_receipt_hash == first.receipt.receipt_hash
    assert verify_receipt_hash(second.receipt) is True
    assert second.final_decision == Decision.HUMAN_REVIEW

def test_dashboard_dict_contains_judge_friendly_summary():
    result = run_axiomguard_pipeline(
        action=make_high_value_invoice_action(),
        lobstertrap_findings=LobsterTrapFinding(risk_score=12),
    )

    dashboard = result.to_dashboard_dict()

    assert dashboard["final_decision"] == "HUMAN_REVIEW"
    assert dashboard["matched_policy"] == "FIN-001"
    assert dashboard["allowed_to_execute"] is False
    assert dashboard["executed"] is False
    assert dashboard["action"]["action_type"] == "approve_invoice"
    assert dashboard["action"]["amount_usd"] == 52000
    assert dashboard["lobstertrap"]["risk_score"] == 12
    assert dashboard["lnn"]["human_review"][0] >= 0.90
    assert dashboard["receipt_hash"].startswith("sha256:")