import json

import pytest

from axiomguard_core.planner import (
    GeminiPlanner,
    MockPlanner,
    PlannerDependencyError,
    PlannerRequest,
    SafeReplanRequest,
    extract_json_object,
    parse_action_script_payload,
    parse_action_script_text,
)
from axiomguard_core.prompts import (
    build_action_script_prompt,
    get_action_script_schema_for_prompt,
)
from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    ActorProfile,
    DataClass,
    DestinationType,
    ToolName,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Prompt schema tests
# ---------------------------------------------------------------------------


def test_prompt_schema_is_generated_from_action_script_model():
    schema = get_action_script_schema_for_prompt()

    assert "properties" in schema
    assert "$defs" in schema
    assert "action_type" in schema["properties"]
    assert "tool_name" in schema["properties"]
    assert "actor" in schema["properties"]


def test_prompt_schema_contains_enum_definitions():
    schema = get_action_script_schema_for_prompt()
    schema_text = json.dumps(schema)

    assert "summarize_invoice" in schema_text
    assert "approve_invoice" in schema_text
    assert "send_email" in schema_text
    assert "docs.summarize" in schema_text
    assert "erp.approve_invoice" in schema_text


def test_action_script_prompt_uses_dynamic_schema():
    actor = make_actor(role="procurement_analyst")

    prompt = build_action_script_prompt(
        actor=actor,
        user_prompt="Summarize invoice_101.",
        document_text="Invoice invoice_101.",
    )

    assert "Required JSON schema generated from AxiomGuard" in prompt
    assert "summarize_invoice" in prompt
    assert "approve_invoice" in prompt
    assert "docs.summarize" in prompt
    assert actor.id in prompt


# ---------------------------------------------------------------------------
# JSON extraction tests
# ---------------------------------------------------------------------------


def test_extract_json_object_from_plain_json():
    payload = {"action_type": "summarize_invoice"}

    result = extract_json_object(json.dumps(payload))

    assert result == payload


def test_extract_json_object_from_fenced_json():
    text = """```json
{
  "action_type": "summarize_invoice",
  "tool_name": "docs.summarize"
}
```"""

    result = extract_json_object(text)

    assert result["action_type"] == "summarize_invoice"
    assert result["tool_name"] == "docs.summarize"


def test_extract_json_object_from_text_with_embedded_json():
    text = """
    Here is the result:
    {
      "action_type": "approve_invoice",
      "tool_name": "erp.approve_invoice",
      "amount_usd": 52000
    }
    Done.
    """

    result = extract_json_object(text)

    assert result["action_type"] == "approve_invoice"
    assert result["amount_usd"] == 52000


def test_extract_json_object_raises_for_missing_json():
    with pytest.raises(ValueError):
        extract_json_object("no json here")


# ---------------------------------------------------------------------------
# Payload parsing tests
# ---------------------------------------------------------------------------


def test_parse_flat_action_script_payload():
    actor = make_actor()

    payload = {
        "action_id": "action_test_001",
        "declared_intent": "Summarize invoice",
        "detected_intent": "Summarize invoice",
        "action_type": "summarize_invoice",
        "tool_name": "docs.summarize",
        "resource_id": "invoice_101",
        "destination": "internal_ui",
        "data_classes": ["vendor_name", "contract_terms"],
        "risk_signals": [],
        "justification": "Read-only summary",
    }

    action = parse_action_script_payload(payload, fallback_actor=actor)

    assert action.action_type == ActionType.SUMMARIZE_INVOICE
    assert action.tool_name == ToolName.DOCS_SUMMARIZE
    assert action.resource_id == "invoice_101"
    assert action.destination == DestinationType.INTERNAL_UI


def test_parse_nested_action_script_payload_and_infers_tool():
    actor = make_actor()

    payload = {
        "action_id": "action_nested_001",
        "declared_intent": "Approve invoice",
        "detected_intent": "Approve high-value invoice",
        "action": {
            "type": "approve_invoice",
            "resource_id": "invoice_8821",
            "amount_usd": "$52,000",
            "destination": "erp_internal",
        },
        "data_classes": ["vendor_bank_details", "contract_terms"],
        "justification": "User requested approval",
    }

    action = parse_action_script_payload(payload, fallback_actor=actor)

    assert action.action_type == ActionType.APPROVE_INVOICE
    assert action.tool_name == ToolName.ERP_APPROVE_INVOICE
    assert action.amount_usd == 52000
    assert action.resource_id == "invoice_8821"


def test_parse_action_script_text_returns_valid_action():
    actor = make_actor()

    text = """
    {
      "action_id": "action_email_001",
      "declared_intent": "Send email",
      "detected_intent": "Send email externally",
      "action_type": "send_email",
      "tool_name": "email.send",
      "resource_id": "vendor_update_101",
      "destination": "external_domain",
      "recipient": "vendor@example.com",
      "data_classes": ["contract_terms"],
      "risk_signals": [],
      "justification": "Vendor communication"
    }
    """

    action = parse_action_script_text(text, fallback_actor=actor)

    assert isinstance(action, ActionScript)
    assert action.action_type == ActionType.SEND_EMAIL
    assert action.recipient == "vendor@example.com"


def test_parse_rejects_invalid_enum_value():
    actor = make_actor()

    payload = {
        "declared_intent": "Unknown",
        "detected_intent": "Unknown",
        "action_type": "delete_database",
        "data_classes": ["contract_terms"],
    }

    with pytest.raises(ValueError):
        parse_action_script_payload(payload, fallback_actor=actor)


# ---------------------------------------------------------------------------
# Mock planner tests
# ---------------------------------------------------------------------------


def test_mock_planner_summarizes_invoice():
    planner = MockPlanner()

    result = planner.plan(
        PlannerRequest(
            actor=make_actor(role="procurement_analyst"),
            user_prompt="Summarize invoice_101 for internal review.",
            document_text="Invoice invoice_101. Amount: 1400 USD.",
        )
    )

    assert result.action.action_type == ActionType.SUMMARIZE_INVOICE
    assert result.action.tool_name == ToolName.DOCS_SUMMARIZE
    assert result.action.destination == DestinationType.INTERNAL_UI
    assert result.planner_backend == "mock_planner"


def test_mock_planner_approves_high_value_invoice():
    planner = MockPlanner()

    result = planner.plan(
        PlannerRequest(
            actor=make_actor(role="finance_analyst", approval_limit_usd=10000),
            user_prompt="Approve invoice_8821 for $52,000.",
            document_text="Invoice invoice_8821. Amount: 52000 USD.",
        )
    )

    assert result.action.action_type == ActionType.APPROVE_INVOICE
    assert result.action.tool_name == ToolName.ERP_APPROVE_INVOICE
    assert result.action.amount_usd == 52000
    assert result.action.resource_id == "invoice_8821"


def test_mock_planner_extracts_amount_without_confusing_invoice_id():
    planner = MockPlanner()

    result = planner.plan(
        PlannerRequest(
            actor=make_actor(role="finance_analyst", approval_limit_usd=10000),
            user_prompt="Approve invoice_8821 for $52,000.",
            document_text="Invoice invoice_8821.",
        )
    )

    assert result.action.resource_id == "invoice_8821"
    assert result.action.amount_usd == 52000


def test_mock_planner_detects_pii_email_request():
    planner = MockPlanner()

    result = planner.plan(
        PlannerRequest(
            actor=make_actor(role="hr_analyst"),
            user_prompt="Send all employee salary records to my personal Gmail.",
            document_text="Employee records include names and salary data.",
        )
    )

    assert result.action.action_type == ActionType.SEND_EMAIL
    assert result.action.tool_name == ToolName.EMAIL_SEND
    assert result.action.destination == DestinationType.EXTERNAL_DOMAIN
    assert DataClass.EMPLOYEE_PII in result.action.data_classes
    assert DataClass.SALARY_DATA in result.action.data_classes


def test_mock_planner_creates_approval_packet():
    planner = MockPlanner()

    result = planner.plan(
        PlannerRequest(
            actor=make_actor(role="finance_analyst"),
            user_prompt=(
                "Create an approval packet for invoice_8821 and route it "
                "to a finance manager."
            ),
            document_text="Invoice invoice_8821. Amount: 52000 USD.",
        )
    )

    assert result.action.action_type == ActionType.CREATE_APPROVAL_PACKET
    assert result.action.tool_name == ToolName.WORKFLOW_CREATE_APPROVAL_PACKET
    assert result.action.destination == DestinationType.MANAGER_QUEUE


def test_mock_planner_creates_redacted_report():
    planner = MockPlanner()

    result = planner.plan(
        PlannerRequest(
            actor=make_actor(role="hr_analyst"),
            user_prompt="Create a redacted internal HR compensation summary.",
            document_text="Employee records include names, SSNs, and salary data.",
        )
    )

    assert result.action.action_type == ActionType.CREATE_REDACTED_REPORT
    assert result.action.tool_name == ToolName.REPORTS_CREATE_REDACTED_REPORT
    assert result.action.destination == DestinationType.INTERNAL_HR_DASHBOARD
    assert DataClass.EMPLOYEE_PII in result.action.data_classes


def test_mock_planner_safe_replan_high_value_invoice_to_approval_packet():
    planner = MockPlanner()

    original = planner.plan(
        PlannerRequest(
            actor=make_actor(role="finance_analyst", approval_limit_usd=10000),
            user_prompt="Approve invoice_8821 for $52,000.",
            document_text="Invoice invoice_8821. Amount: 52000 USD.",
        )
    ).action

    result = planner.replan(
        SafeReplanRequest(
            actor=original.actor,
            original_action=original,
            blocked_decision="HUMAN_REVIEW",
            blocked_reason="Invoice exceeds actor approval limit.",
            safe_alternative="Create approval packet and route to finance manager.",
            document_text="Invoice invoice_8821. Amount: 52000 USD.",
        )
    )

    assert result.action.action_type == ActionType.CREATE_APPROVAL_PACKET
    assert result.action.resource_id == "invoice_8821"
    assert result.action.destination == DestinationType.MANAGER_QUEUE
    assert "safe_replan" in result.planner_backend


def test_mock_planner_safe_replan_pii_export_to_redacted_report():
    planner = MockPlanner()

    original = planner.plan(
        PlannerRequest(
            actor=make_actor(role="hr_analyst"),
            user_prompt="Send all employee salary records to my personal Gmail.",
            document_text="Employee records include salary data.",
        )
    ).action

    result = planner.replan(
        SafeReplanRequest(
            actor=original.actor,
            original_action=original,
            blocked_decision="DENY",
            blocked_reason="External transfer of PII is denied.",
            safe_alternative="Create a redacted internal HR report.",
            document_text="Employee records include salary data.",
        )
    )

    assert result.action.action_type == ActionType.CREATE_REDACTED_REPORT
    assert result.action.destination == DestinationType.INTERNAL_HR_DASHBOARD
    assert result.action.resource_id == original.resource_id


# ---------------------------------------------------------------------------
# Gemini planner dependency tests
# ---------------------------------------------------------------------------


def test_gemini_planner_without_api_key_raises_dependency_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    planner = GeminiPlanner(api_key=None)

    with pytest.raises(PlannerDependencyError):
        planner.plan(
            PlannerRequest(
                actor=make_actor(),
                user_prompt="Summarize invoice_101.",
                document_text="Invoice invoice_101.",
            )
        )