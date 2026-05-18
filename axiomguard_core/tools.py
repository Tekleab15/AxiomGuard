"""
Simulated enterprise tools for AxiomGuard.

These tools represent the high-impact enterprise actions that AI agents
must not execute without governance:

- ERP invoice approval
- email sending
- document summarization
- approval packet creation
- redacted report generation

Security principle:
No valid ALLOW Decision Receipt, no tool execution.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from axiomguard_core.receipts import assert_receipt_allows_execution
from axiomguard_core.schemas import (
    ActionType,
    DataClass,
    DecisionReceipt,
    ToolName,
    ToolResult,
)


SimulatedToolHandler = Callable[[DecisionReceipt], dict[str, Any]]

# ----------------------------------
# Tool/action compatibility
# -----------------------------------

TOOL_ACTION_COMPATIBILITY: dict[ToolName, set[ActionType]] = {
    ToolName.DOCS_SUMMARIZE: {
        ActionType.SUMMARIZE_INVOICE,
        ActionType.SUMMARIZE_CONTRACT,
    },
    ToolName.ERP_APPROVE_INVOICE: {
        ActionType.APPROVE_INVOICE,
    },
    ToolName.EMAIL_SEND: {
        ActionType.SEND_EMAIL,
    },
    ToolName.WORKFLOW_CREATE_APPROVAL_PACKET: {
        ActionType.CREATE_APPROVAL_PACKET,
    },
    ToolName.REPORTS_CREATE_REDACTED_REPORT: {
        ActionType.CREATE_REDACTED_REPORT,
    },
}

def is_tool_action_compatible(
    tool_name: ToolName,
    action_type: ActionType,
) -> bool:
    """
    Defense-in-depth compatibility check.

    The deterministic gate already checks tool/action compatibility,
    but the executor repeats this check so tool calls cannot bypass policy.
    """

    allowed_actions = TOOL_ACTION_COMPATIBILITY.get(tool_name, set())
    return action_type in allowed_actions

def assert_tool_action_compatible(receipt: DecisionReceipt) -> None:
    """
    Raise PermissionError if the receipt's tool does not match its action type.
    """
    action = receipt.action

    if not is_tool_action_compatible(action.tool_name, action.action_type):
        raise PermissionError(
            f"Tool/action mismatch. Tool '{action.tool_name.value}' cannot execute "
            f"action '{action.action_type.value}'."
        )

# ---------------------------------------------------------------------------
# Simulated enterprise tool handlers
# ---------------------------------------------------------------------------

def simulate_document_summary(receipt: DecisionReceipt) -> dict[str, Any]:
    """
    Simulate a read-only document summarization workflow.
    """
    action = receipt.action

    document_type = (
        "invoice"
        if action.action_type == ActionType.SUMMARIZE_INVOICE
        else "contract"
    )

    return {
        "tool": ToolName.DOCS_SUMMARIZE.value,
        "document_type": document_type,
        "resource_id": action.resource_id,
        "summary": (
            f"Simulated {document_type} summary for resource "
            f"'{action.resource_id}'. The action was read-only and internal."
        ),
        "data_classes_seen": [item.value for item in action.data_classes],
        "external_transfer": False,
        "simulated": True,
    }

def simulate_erp_invoice_approval(receipt: DecisionReceipt) -> dict[str, Any]:
    """
    Simulate ERP invoice approval.

    This function should only run for valid ALLOW receipts.
    """
    action = receipt.action

    return {
        "tool": ToolName.ERP_APPROVE_INVOICE.value,
        "approval_id": f"SIM-APPROVAL-{action.resource_id}",
        "resource_id": action.resource_id,
        "approved_amount_usd": action.amount_usd,
        "approved_by": action.actor.id,
        "actor_role": action.actor.role,
        "destination": action.destination.value,
        "simulated": True,
    }

def simulate_email_send(receipt: DecisionReceipt) -> dict[str, Any]:
    """
    Simulate email sending.
    This never sends a real email. It only records what would have happened.
    """
    action = receipt.action

    return {
        "tool": ToolName.EMAIL_SEND.value,
        "message_id": f"SIM-EMAIL-{action.action_id}",
        "recipient": action.recipient,
        "resource_id": action.resource_id,
        "subject": f"AxiomGuard simulated message for {action.resource_id}",
        "body_preview": "This is a simulated email. No real message was sent.",
        "delivery_mode": "simulated_only",
        "simulated": True,
    }

def simulate_approval_packet_creation(receipt: DecisionReceipt) -> dict[str, Any]:
    """
    Simulate creation of a human-review approval packet.
    """
    action = receipt.action

    return {
        "tool": ToolName.WORKFLOW_CREATE_APPROVAL_PACKET.value,
        "packet_id": f"SIM-PACKET-{action.resource_id}",
        "resource_id": action.resource_id,
        "created_by": action.actor.id,
        "reviewer_role": "finance_manager",
        "destination": action.destination.value,
        "included_evidence_count": len(action.evidence),
        "simulated": True,
    }

def simulate_redacted_report_creation(receipt: DecisionReceipt) -> dict[str, Any]:
    """
    Simulate creation of an internal redacted report.
    """

    action = receipt.action

    redactions = infer_redactions(action.data_classes)

    return {
        "tool": ToolName.REPORTS_CREATE_REDACTED_REPORT.value,
        "report_id": f"SIM-REPORT-{action.resource_id}",
        "resource_id": action.resource_id,
        "destination": action.destination.value,
        "redactions": redactions,
        "data_classes_after_redaction": [DataClass.AGGREGATED_HR_METRICS.value],
        "simulated": True,
    }

def infer_redactions(data_classes: list[DataClass]) -> list[str]:
    """
    Infer human-readable redaction names from data classes.
    """

    redactions: list[str] = []

    if DataClass.EMPLOYEE_PII in data_classes:
        redactions.extend(["employee_name", "employee_email", "employee_id"])

    if DataClass.CUSTOMER_PII in data_classes:
        redactions.extend(["customer_name", "customer_email", "customer_id"])

    if DataClass.SALARY_DATA in data_classes:
        redactions.append("salary")

    if DataClass.SSN in data_classes:
        redactions.append("ssn")

    if DataClass.VENDOR_BANK_DETAILS in data_classes:
        redactions.extend(["bank_account", "routing_number"])

    if DataClass.CREDENTIAL in data_classes:
        redactions.append("credential")

    if DataClass.SECRET in data_classes:
        redactions.append("secret")

    if not redactions:
        redactions.append("none_required")

    return sorted(set(redactions))

# -------------------------------
# Registry
# -------------------------------

SIMULATED_TOOL_REGISTRY: dict[ToolName, SimulatedToolHandler] = {
    ToolName.DOCS_SUMMARIZE: simulate_document_summary,
    ToolName.ERP_APPROVE_INVOICE: simulate_erp_invoice_approval,
    ToolName.EMAIL_SEND: simulate_email_send,
    ToolName.WORKFLOW_CREATE_APPROVAL_PACKET: simulate_approval_packet_creation,
    ToolName.REPORTS_CREATE_REDACTED_REPORT: simulate_redacted_report_creation,
}

def get_supported_tool_names() -> list[str]:
    """
    Return supported simulated tool names for UI and docs.
    """

    return sorted([tool.value for tool in SIMULATED_TOOL_REGISTRY])

def is_supported_tool(tool_name: ToolName) -> bool:
    """
    Return whether a tool is registered.
    """
    return tool_name in SIMULATED_TOOL_REGISTRY

# -------------------------------------
# Receipt-required executor
# -------------------------------------

def execute_authorized_tool(receipt: DecisionReceipt) -> ToolResult:
    """
    Execute the simulated enterprise tool authorized by a Decision Receipt.

    This function raises PermissionError if:
    - the receipt hash is missing or invalid
    - the receipt final decision is not ALLOW
    - the tool/action combination is invalid
    - the tool is not registered

    This is the core implementation of:
        No valid ALLOW receipt, no tool call.
    """

    assert_receipt_allows_execution(receipt)
    assert_tool_action_compatible(receipt)

    action = receipt.action
    handler = SIMULATED_TOOL_REGISTRY.get(action.tool_name)

    if handler is None:
        raise PermissionError(
            f"Tool '{action.tool_name.value}' is not registered."
        )

    output = handler(receipt)

    return ToolResult(
        tool_name=action.tool_name,
        receipt_id=receipt.receipt_id,
        executed=True,
        status="simulated_execution_complete",
        output=output,
        blocked_reason=None,
    )

def attempt_tool_execution(receipt: DecisionReceipt) -> ToolResult:
    """
    Dashboard-friendly execution wrapper.

    Instead of raising PermissionError for blocked calls, this returns a
    ToolResult with executed=False and a blocked_reason.

    Use this for Streamlit and red-team replay views.
    Use execute_authorized_tool for strict backend enforcement.
    """

    try:
        return execute_authorized_tool(receipt)
    except PermissionError as exc:
        return ToolResult(
            tool_name=receipt.action.tool_name,
            receipt_id=receipt.receipt_id,
            executed=False,
            status="blocked_by_axiomguard",
            output={},
            blocked_reason=str(exc),
        )