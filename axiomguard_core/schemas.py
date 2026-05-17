"""
AxiomGuard shared data contracts.

This module defines the typed boundaries between:
- Gemini planner
- Lobster Trap inspection
- AxiomLNN verifier
- deterministic execution gate
- simulated enterprise tools
- Decision Receipt generator
- red-team runner

Design principle:
No tool execution should happen without a valid DecisionReceipt
whose final decision is ALLOW.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------
# Enums
# ---------------------------

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REDACT = "REDACT"
    QUARANTINE = "QUARANTINE"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    RATE_LIMIT = "RATE_LIMIT"

class ExecutionStatus(str, Enum):
    EXECUTED = "executed"
    NOT_EXECUTED = "not_executed"
    BLOCKED_DENIED = "blocked_denied"
    BLOCKED_QUARANTINED = "blocked_quarantined"
    BLOCKED_PENDING_REVIEW = "blocked_pending_review"
    REDACTION_REQUIRED = "redaction_required"
    RATE_LIMITED = "rate_limited"
    FAILED_VALIDATION = "failed_validation"

class ActionType(str, Enum):
    SUMMARIZE_INVOICE = "summarize_invoice"
    SUMMARIZE_CONTRACT = "summarize_contract"
    APPROVE_INVOICE = "approve_invoice"
    SEND_EMAIL = "send_email"
    CREATE_APPROVAL_PACKET = "create_approval_packet"
    CREATE_REDACTED_REPORT = "create_redacted_report"

class ToolName(str, Enum):
    DOCS_SUMMARIZE = "docs.summarize"
    ERP_APPROVE_INVOICE = "erp.approve_invoice"
    EMAIL_SEND = "email.send"
    WORKFLOW_CREATE_APPROVAL_PACKET = "workflow.create_approval_packet"
    REPORTS_CREATE_REDACTED_REPORT = "reports.create_redacted_report"

class DestinationType(str, Enum):
    INTERNAL_UI = "internal_ui"
    ERP_INTERNAL = "erp_internal"
    MANAGER_QUEUE = "manager_queue"
    INTERNAL_HR_DASHBOARD = "internal_hr_dashboard"
    EXTERNAL_DOMAIN = "external_domain"
    UNKNOWN = "unknown"

class DataClass(str, Enum):
    NONE = "none"
    VENDOR_NAME = "vendor_name"
    CONTRACT_TERMS = "contract_terms"
    VENDOR_BANK_DETAILS = "vendor_bank_details"
    EMPLOYEE_PII = "employee_pii"
    CUSTOMER_PII = "customer_pii"
    SALARY_DATA = "salary_data"
    SSN = "ssn"
    CREDENTIAL = "credential"
    SECRET = "secret"
    AGGREGATED_HR_METRICS = "aggregated_hr_metrics"

class RiskSignal(str, Enum):
    FINANCIAL_ACTION = "financial_action"
    HIGH_VALUE_TRANSACTION = "high_value_transaction"
    PROMPT_INJECTION = "prompt_injection"
    EXFILTRATION = "exfiltration"
    PII_DETECTED = "pii_detected"
    CREDENTIAL_DETECTED = "credential_detected"
    RISKY_COMMAND = "risky_command"
    INTENT_MISMATCH = "intent_mismatch"
    UNKNOWN = "unknown"

# ----------------------------------------
# Core request and action schemas
# ----------------------------------------

class ActorProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, description="Enterprise user or service identity.")
    role: str = Field(..., min_length=1, description="Business role, e.g. finance_analyst.")
    department: str = Field(default="unknown", description="Department or business unit.")
    approval_limit_usd: float = Field(
        default=0.0,
        ge=0.0,
        description="Maximum invoice approval amount for this actor.",
    )

class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., description="Source document, prompt, model output, or policy.")
    field: str = Field(..., description="Field or location where evidence was found.")
    excerpt: str = Field(..., description="Short supporting excerpt.")

class ActionScript(BaseModel):
    """
    Structured action proposed by Gemini.
    Gemini may propose actions, but this object is never trusted by itself.
    It must be inspected, verified, enforced, and receipted before execution.
    """
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(..., min_length=1)
    actor: ActorProfile

    declared_intent: str = Field(..., min_length=1)
    detected_intent: str = Field(default="unknown")

    action_type: ActionType
    tool_name: ToolName
    resource_id: str = Field(default="unknown")

    amount_usd: Optional[float] = Field(default=None, ge=0.0)
    destination: DestinationType = DestinationType.UNKNOWN
    recipient: Optional[str] = None

    data_classes: list[DataClass] = Field(default_factory=lambda: [DataClass.NONE])
    risk_signals: list[RiskSignal] = Field(default_factory=list)

    justification: str = Field(default="")
    evidence: list[EvidenceItem] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_action_requirements(self) -> "ActionScript":
        if self.action_type == ActionType.APPROVE_INVOICE and self.amount_usd is None:
            raise ValueError("approve_invoice actions require amount_usd.")

        if self.action_type == ActionType.SEND_EMAIL and not self.recipient:
            raise ValueError("send_email actions require recipient.")

        if self.destination == DestinationType.EXTERNAL_DOMAIN and not self.recipient:
            raise ValueError("external_domain actions require recipient.")

        return self

    @property
    def touches_sensitive_data(self) -> bool:
        sensitive = {
            DataClass.VENDOR_BANK_DETAILS,
            DataClass.EMPLOYEE_PII,
            DataClass.CUSTOMER_PII,
            DataClass.SALARY_DATA,
            DataClass.SSN,
            DataClass.CREDENTIAL,
            DataClass.SECRET,
        }
        return any(item in sensitive for item in self.data_classes)

    @property
    def is_external_transfer(self) -> bool:
        return self.destination == DestinationType.EXTERNAL_DOMAIN

    @property
    def is_high_value_transaction(self) -> bool:
        return (
            self.action_type == ActionType.APPROVE_INVOICE
            and self.amount_usd is not None
            and self.amount_usd > self.actor.approval_limit_usd
        )

# ------------------------------------------
# Tool execution schemas
# ------------------------------------------

class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: ToolName
    receipt_id: str
    executed: bool
    status: str
    output: dict[str, Any] = Field(default_factory=dict)
    blocked_reason: Optional[str] = None

# --------------------------------------------
# Red-team schemas
# --------------------------------------------

class RedTeamScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str

    actor: ActorProfile
    user_prompt: str
    document_text: str = ""

    expected_baseline_behavior: str
    expected_axiomguard_decision: Decision

    tags: list[str] = Field(default_factory=list)

class RedTeamResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    scenario_name: str

    baseline_result: str
    axiomguard_decision: Decision
    passed: bool

    receipt_id: Optional[str] = None
    notes: str = ""