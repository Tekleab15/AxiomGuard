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
    
# -------------------------------------
# Lobster Trap metadata schema
# -------------------------------------

class LobsterTrapFinding(BaseModel):
    """
    Normalized Lobster Trap result.
    Internally, AxiomGuard uses risk_score on a 0-100 scale.
    If an external tool returns a 0-1 score, this schema normalizes it.
    """
    model_config = ConfigDict(extra="forbid")

    prompt_injection: bool = False
    exfiltration_detected: bool = False
    pii_detected: bool = False
    credential_detected: bool = False
    risky_command_detected: bool = False
    intent_mismatch: bool = False

    detected_domains: list[str] = Field(default_factory=list)
    target_paths: list[str] = Field(default_factory=list)

    declared_intent_category: str = "unknown"
    detected_intent_category: str = "unknown"

    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)

    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("risk_score", mode="before")
    @classmethod
    def normalize_risk_score(cls, value: Any) -> float:
        score = float(value)

        # Lobster Trap or other scanners may output 0.0-1.0.
        # AxiomGuard normalizes to 0-100 for dashboard readability.
        if 0.0 < score <= 1.0:
            return round(score * 100.0, 2)

        return score

    @property
    def should_quarantine_from_trap(self) -> bool:
        return self.prompt_injection or self.exfiltration_detected or self.risk_score >= 90.0

# -----------------------------
# LNN / verifier schemas
# -----------------------------

class TruthBound(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lower: float = Field(default=0.0, ge=0.0, le=1.0)
    upper: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_bounds(self) -> "TruthBound":
        if self.lower > self.upper:
            raise ValueError("TruthBound.lower cannot be greater than TruthBound.upper.")
        return self

    @classmethod
    def point(cls, value: float) -> "TruthBound":
        return cls(lower=value, upper=value)

class MatchedFormula(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str
    decision: Decision
    formula: str
    score: float = Field(..., ge=0.0, le=1.0)
    trace: str

class AxiomLNNInference(BaseModel):
    """
    Output of the AxiomLNN verifier.
    The deterministic gate will convert these truth bounds into a final decision.
    """
    model_config = ConfigDict(extra="forbid")

    allow: TruthBound = Field(default_factory=TruthBound)
    deny: TruthBound = Field(default_factory=TruthBound)
    redact: TruthBound = Field(default_factory=TruthBound)
    quarantine: TruthBound = Field(default_factory=TruthBound)
    human_review: TruthBound = Field(default_factory=TruthBound)
    rate_limit: TruthBound = Field(default_factory=TruthBound)

    contradiction_loss: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_formulas: list[MatchedFormula] = Field(default_factory=list)

    facts: dict[str, bool | float | str] = Field(default_factory=dict)
    trace: str = Field(default="")

    def score_for(self, decision: Decision) -> float:
        if decision == Decision.ALLOW:
            return self.allow.lower
        if decision == Decision.DENY:
            return self.deny.lower
        if decision == Decision.REDACT:
            return self.redact.lower
        if decision == Decision.QUARANTINE:
            return self.quarantine.lower
        if decision == Decision.HUMAN_REVIEW:
            return self.human_review.lower
        if decision == Decision.RATE_LIMIT:
            return self.rate_limit.lower
        return 0.0

# -----------------------------------------
# Enforcement and receipt schemas
# -----------------------------------------

class EnforcementDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    reason: str
    matched_policy: str = "none"
    safe_alternative: Optional[str] = None
    execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED

    @property
    def allowed_to_execute(self) -> bool:
        return self.decision == Decision.ALLOW

class DecisionReceipt(BaseModel):
    """
    Audit-ready record for the agent action.
    This is the artifact shown to judges, CISOs, compliance teams, and regulators.
    """
    model_config = ConfigDict(extra="forbid")

    receipt_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    agent: str = "procurement_copilot"
    action: ActionScript
    lobstertrap_findings: LobsterTrapFinding
    lnn_inference: AxiomLNNInference
    enforcement: EnforcementDecision

    receipt_hash: Optional[str] = None
    previous_receipt_hash: Optional[str] = None

    version: str = "1.0"

    @property
    def final_decision(self) -> Decision:
        return self.enforcement.decision
    @property
    def allowed_to_execute(self) -> bool:
        return self.enforcement.allowed_to_execute