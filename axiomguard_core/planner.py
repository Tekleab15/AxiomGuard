"""
Planner layer for AxiomGuard.

This module provides:
- MockPlanner for deterministic local development and tests
- GeminiPlanner for live Google Gemini integration
- JSON extraction and normalization into ActionScript

Security principle:
The planner only proposes actions. It never executes tools and never makes
the final safety decision.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from dotenv import load_dotenv

load_dotenv()
from axiomguard_core.prompts import (
    build_action_script_prompt,
    build_safe_replan_prompt,
)
from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    ActorProfile,
    DataClass,
    DestinationType,
    EvidenceItem,
    RiskSignal,
    ToolName,
)


# ---------------------------------------------------------------------------
# Planner request / result models
# ---------------------------------------------------------------------------


class PlannerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: ActorProfile
    user_prompt: str = Field(..., min_length=1)
    document_text: str = ""
    extra_context: str = ""


class PlannerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: ActionScript
    raw_model_output: str
    planner_backend: str
    warnings: list[str] = Field(default_factory=list)


class SafeReplanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: ActorProfile
    original_action: ActionScript
    blocked_decision: str
    blocked_reason: str
    safe_alternative: str | None = None
    document_text: str = ""


class PlannerDependencyError(RuntimeError):
    """
    Raised when a live planner dependency is missing.
    """


class Planner(Protocol):
    def plan(self, request: PlannerRequest) -> PlannerResult:
        ...

    def replan(self, request: SafeReplanRequest) -> PlannerResult:
        ...


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


DEFAULT_TOOL_BY_ACTION: dict[ActionType, ToolName] = {
    ActionType.SUMMARIZE_INVOICE: ToolName.DOCS_SUMMARIZE,
    ActionType.SUMMARIZE_CONTRACT: ToolName.DOCS_SUMMARIZE,
    ActionType.APPROVE_INVOICE: ToolName.ERP_APPROVE_INVOICE,
    ActionType.SEND_EMAIL: ToolName.EMAIL_SEND,
    ActionType.CREATE_APPROVAL_PACKET: ToolName.WORKFLOW_CREATE_APPROVAL_PACKET,
    ActionType.CREATE_REDACTED_REPORT: ToolName.REPORTS_CREATE_REDACTED_REPORT,
}


DEFAULT_DESTINATION_BY_ACTION: dict[ActionType, DestinationType] = {
    ActionType.SUMMARIZE_INVOICE: DestinationType.INTERNAL_UI,
    ActionType.SUMMARIZE_CONTRACT: DestinationType.INTERNAL_UI,
    ActionType.APPROVE_INVOICE: DestinationType.ERP_INTERNAL,
    ActionType.SEND_EMAIL: DestinationType.EXTERNAL_DOMAIN,
    ActionType.CREATE_APPROVAL_PACKET: DestinationType.MANAGER_QUEUE,
    ActionType.CREATE_REDACTED_REPORT: DestinationType.INTERNAL_HR_DASHBOARD,
}


def extract_json_object(text: str) -> dict[str, Any]:
    """
    Extract a JSON object from a raw model response.

    Supports:
    - pure JSON
    - ```json fenced JSON
    - explanatory text with a JSON object embedded inside
    """

    stripped = text.strip()

    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.IGNORECASE).strip()
        stripped = re.sub(r"```$", "", stripped).strip()

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = stripped.find("{")
    end = stripped.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON object could be extracted from model output.")

    candidate = stripped[start : end + 1]
    parsed = json.loads(candidate)

    if not isinstance(parsed, dict):
        raise ValueError("Extracted JSON payload is not an object.")

    return parsed


def parse_action_script_payload(
    payload: dict[str, Any],
    *,
    fallback_actor: ActorProfile,
) -> ActionScript:
    """
    Normalize Gemini or mock JSON into an ActionScript.

    Supports both flat format:
        action_type, tool_name, resource_id

    and nested format:
        action: { type, tool_name, resource_id, amount_usd, destination }
    """

    action_block = payload.get("action", {})
    if action_block is None:
        action_block = {}

    if not isinstance(action_block, dict):
        raise ValueError("'action' field must be an object when provided.")

    actor_payload = payload.get("actor")
    actor = (
        ActorProfile.model_validate(actor_payload)
        if isinstance(actor_payload, dict)
        else fallback_actor
    )

    action_type = _normalize_enum(
        ActionType,
        payload.get("action_type")
        or action_block.get("type")
        or action_block.get("action_type"),
        "action_type",
    )

    tool_name_raw = (
        payload.get("tool_name")
        or action_block.get("tool")
        or action_block.get("tool_name")
    )

    tool_name = (
        _normalize_enum(ToolName, tool_name_raw, "tool_name")
        if tool_name_raw
        else DEFAULT_TOOL_BY_ACTION[action_type]
    )

    destination_raw = (
        payload.get("destination")
        or action_block.get("destination")
    )

    destination = (
        _normalize_enum(DestinationType, destination_raw, "destination")
        if destination_raw
        else DEFAULT_DESTINATION_BY_ACTION[action_type]
    )

    data_classes = [
        _normalize_enum(DataClass, item, "data_classes")
        for item in payload.get("data_classes", [DataClass.NONE.value])
    ]

    risk_signals = [
        _normalize_enum(RiskSignal, item, "risk_signals")
        for item in payload.get("risk_signals", [])
    ]

    evidence_payload = payload.get("evidence", [])
    evidence = [
        EvidenceItem.model_validate(item)
        for item in evidence_payload
        if isinstance(item, dict)
    ]

    action_id = (
        payload.get("action_id")
        or action_block.get("id")
        or f"action_{uuid.uuid4().hex[:8]}"
    )

    return ActionScript(
        action_id=str(action_id),
        actor=actor,
        declared_intent=str(payload.get("declared_intent", "unknown")),
        detected_intent=str(payload.get("detected_intent", "unknown")),
        action_type=action_type,
        tool_name=tool_name,
        resource_id=str(
            payload.get("resource_id")
            or action_block.get("resource_id")
            or "unknown"
        ),
        amount_usd=_optional_float(
            payload.get("amount_usd")
            if "amount_usd" in payload
            else action_block.get("amount_usd")
        ),
        destination=destination,
        recipient=(
            payload.get("recipient")
            if payload.get("recipient") is not None
            else action_block.get("recipient")
        ),
        data_classes=data_classes,
        risk_signals=risk_signals,
        justification=str(payload.get("justification", "")),
        evidence=evidence,
    )


def parse_action_script_text(
    text: str,
    *,
    fallback_actor: ActorProfile,
) -> ActionScript:
    payload = extract_json_object(text)
    return parse_action_script_payload(payload, fallback_actor=fallback_actor)


def _normalize_enum(enum_cls: type, value: Any, field_name: str):
    if value is None:
        raise ValueError(f"Missing required enum field: {field_name}")

    if isinstance(value, enum_cls):
        return value

    normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")

    for member in enum_cls:
        if member.value == normalized or member.name.lower() == normalized:
            return member

    valid = ", ".join(member.value for member in enum_cls)
    raise ValueError(
        f"Invalid value for {field_name}: {value!r}. Expected one of: {valid}"
    )


def _optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None

    if isinstance(value, str):
        cleaned = value.replace("$", "").replace(",", "").strip()
        if not cleaned:
            return None
        return float(cleaned)

    return float(value)


# ---------------------------------------------------------------------------
# Mock planner
# ---------------------------------------------------------------------------


@dataclass
class MockPlanner:
    """
    Deterministic planner for local development, tests, and fallback demos.

    It intentionally mimics Gemini's role:
    user request + document context -> ActionScript

    It does not inspect prompts like Lobster Trap and does not decide safety.
    """

    backend_name: str = "mock_planner"

    def plan(self, request: PlannerRequest) -> PlannerResult:
        prompt = f"{request.user_prompt}\n{request.document_text}".lower()

        if "approval packet" in prompt or ("route" in prompt and "manager" in prompt):
            action = self._create_approval_packet(request)

        elif "redacted" in prompt or "hr compensation summary" in prompt:
            action = self._create_redacted_report(request)

        elif "approve" in prompt and "invoice" in prompt:
            action = self._approve_invoice(request)

        elif "send" in prompt or "email" in prompt or "gmail" in prompt:
            action = self._send_email(request)

        elif "contract" in prompt:
            action = self._summarize_contract(request)

        else:
            action = self._summarize_invoice(request)

        return PlannerResult(
            action=action,
            raw_model_output=action.model_dump_json(indent=2),
            planner_backend=self.backend_name,
            warnings=[],
        )

    def replan(self, request: SafeReplanRequest) -> PlannerResult:
        safe_text = (request.safe_alternative or "").lower()
        reason_text = request.blocked_reason.lower()

        planner_request = PlannerRequest(
            actor=request.actor,
            user_prompt=request.safe_alternative or request.blocked_reason,
            document_text=request.document_text,
        )

        if "approval packet" in safe_text or "finance manager" in safe_text:
            action = self._create_approval_packet(
                planner_request,
                resource_id=request.original_action.resource_id,
            )

        elif "redacted" in safe_text or "pii" in reason_text:
            action = self._create_redacted_report(
                planner_request,
                resource_id=request.original_action.resource_id,
            )

        else:
            action = self._summarize_invoice(
                planner_request,
                resource_id=request.original_action.resource_id,
            )

        return PlannerResult(
            action=action,
            raw_model_output=action.model_dump_json(indent=2),
            planner_backend=f"{self.backend_name}_safe_replan",
            warnings=["Safe replan generated from blocked decision context."],
        )

    def _summarize_invoice(
        self,
        request: PlannerRequest,
        resource_id: str | None = None,
    ) -> ActionScript:
        return ActionScript(
            action_id="mock_summarize_invoice",
            actor=request.actor,
            declared_intent="Summarize invoice for internal review.",
            detected_intent="Summarize invoice for internal review.",
            action_type=ActionType.SUMMARIZE_INVOICE,
            tool_name=ToolName.DOCS_SUMMARIZE,
            resource_id=resource_id or _extract_resource_id(
                request.user_prompt,
                request.document_text,
                default="invoice_101",
            ),
            destination=DestinationType.INTERNAL_UI,
            data_classes=[DataClass.VENDOR_NAME, DataClass.CONTRACT_TERMS],
            justification="Read-only internal invoice summary.",
            evidence=[
                EvidenceItem(
                    source="prompt",
                    field="user_prompt",
                    excerpt=request.user_prompt[:180],
                )
            ],
        )

    def _summarize_contract(self, request: PlannerRequest) -> ActionScript:
        data_classes = [DataClass.CONTRACT_TERMS]

        combined = f"{request.user_prompt}\n{request.document_text}".lower()
        if "bank" in combined or "routing" in combined:
            data_classes.append(DataClass.VENDOR_BANK_DETAILS)

        return ActionScript(
            action_id="mock_summarize_contract",
            actor=request.actor,
            declared_intent="Summarize contract for internal review.",
            detected_intent="Summarize contract for internal review.",
            action_type=ActionType.SUMMARIZE_CONTRACT,
            tool_name=ToolName.DOCS_SUMMARIZE,
            resource_id=_extract_resource_id(
                request.user_prompt,
                request.document_text,
                default="contract_001",
            ),
            destination=DestinationType.INTERNAL_UI,
            data_classes=data_classes,
            justification="Read-only internal contract summary.",
            evidence=[
                EvidenceItem(
                    source="document",
                    field="document_text",
                    excerpt=request.document_text[:180],
                )
            ],
        )

    def _approve_invoice(self, request: PlannerRequest) -> ActionScript:
        amount = _extract_amount_usd(request.user_prompt, request.document_text)

        return ActionScript(
            action_id="mock_approve_invoice",
            actor=request.actor,
            declared_intent="Approve vendor invoice.",
            detected_intent="Execute financial invoice approval.",
            action_type=ActionType.APPROVE_INVOICE,
            tool_name=ToolName.ERP_APPROVE_INVOICE,
            resource_id=_extract_resource_id(
                request.user_prompt,
                request.document_text,
                default="invoice_8821",
            ),
            amount_usd=amount,
            destination=DestinationType.ERP_INTERNAL,
            data_classes=[DataClass.VENDOR_BANK_DETAILS, DataClass.CONTRACT_TERMS],
            risk_signals=[
                RiskSignal.FINANCIAL_ACTION,
                *(
                    [RiskSignal.HIGH_VALUE_TRANSACTION]
                    if amount > request.actor.approval_limit_usd
                    else []
                ),
            ],
            justification="User requested invoice approval.",
            evidence=[
                EvidenceItem(
                    source="prompt",
                    field="amount",
                    excerpt=request.user_prompt[:180],
                )
            ],
        )

    def _send_email(self, request: PlannerRequest) -> ActionScript:
        combined = f"{request.user_prompt}\n{request.document_text}".lower()
        recipient = _extract_email(combined) or "personal@gmail.com"

        data_classes = [DataClass.CONTRACT_TERMS]

        if "employee" in combined or "salary" in combined:
            data_classes = [DataClass.EMPLOYEE_PII, DataClass.SALARY_DATA]

        if "credential" in combined or "api_key" in combined or "secret" in combined:
            data_classes = [DataClass.CREDENTIAL, DataClass.SECRET]

        return ActionScript(
            action_id="mock_send_email",
            actor=request.actor,
            declared_intent="Send email.",
            detected_intent="Send email to external recipient.",
            action_type=ActionType.SEND_EMAIL,
            tool_name=ToolName.EMAIL_SEND,
            resource_id=_extract_resource_id(
                request.user_prompt,
                request.document_text,
                default="email_payload",
            ),
            destination=DestinationType.EXTERNAL_DOMAIN,
            recipient=recipient,
            data_classes=data_classes,
            risk_signals=[
                *(
                    [RiskSignal.PII_DETECTED]
                    if DataClass.EMPLOYEE_PII in data_classes
                    else []
                ),
                *(
                    [RiskSignal.CREDENTIAL_DETECTED]
                    if DataClass.CREDENTIAL in data_classes
                    else []
                ),
            ],
            justification="User requested an email action.",
            evidence=[
                EvidenceItem(
                    source="prompt",
                    field="recipient",
                    excerpt=request.user_prompt[:180],
                )
            ],
        )

    def _create_approval_packet(
        self,
        request: PlannerRequest,
        resource_id: str | None = None,
    ) -> ActionScript:
        return ActionScript(
            action_id="mock_create_approval_packet",
            actor=request.actor,
            declared_intent="Create approval packet for manager review.",
            detected_intent="Create approval packet for manager review.",
            action_type=ActionType.CREATE_APPROVAL_PACKET,
            tool_name=ToolName.WORKFLOW_CREATE_APPROVAL_PACKET,
            resource_id=resource_id
            or _extract_resource_id(
                request.user_prompt,
                request.document_text,
                default="invoice_8821",
            ),
            destination=DestinationType.MANAGER_QUEUE,
            data_classes=[DataClass.VENDOR_BANK_DETAILS, DataClass.CONTRACT_TERMS],
            justification="Safe workflow alternative for high-value approval.",
            evidence=[
                EvidenceItem(
                    source="prompt",
                    field="safe_workflow",
                    excerpt=request.user_prompt[:180],
                )
            ],
        )

    def _create_redacted_report(
        self,
        request: PlannerRequest,
        resource_id: str | None = None,
    ) -> ActionScript:
        return ActionScript(
            action_id="mock_create_redacted_report",
            actor=request.actor,
            declared_intent="Create redacted internal report.",
            detected_intent="Create redacted internal report.",
            action_type=ActionType.CREATE_REDACTED_REPORT,
            tool_name=ToolName.REPORTS_CREATE_REDACTED_REPORT,
            resource_id=resource_id
            or _extract_resource_id(
                request.user_prompt,
                request.document_text,
                default="employee_records",
            ),
            destination=DestinationType.INTERNAL_HR_DASHBOARD,
            data_classes=[
                DataClass.EMPLOYEE_PII,
                DataClass.SALARY_DATA,
                DataClass.SSN,
            ],
            justification="Safe internal redacted report instead of raw data export.",
            evidence=[
                EvidenceItem(
                    source="prompt",
                    field="redaction_request",
                    excerpt=request.user_prompt[:180],
                )
            ],
        )


# ---------------------------------------------------------------------------
# Gemini planner
# ---------------------------------------------------------------------------


@dataclass
class GeminiPlanner:
    """
    Live Gemini planner.

    This adapter intentionally returns ActionScript only.
    It does not call enterprise tools and does not decide whether an action is safe.
    """

    api_key: str | None = None
    model_name: str = field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    )
    backend_name: str = "gemini_planner"
    temperature: float = 0.0

    def plan(self, request: PlannerRequest) -> PlannerResult:
        prompt = build_action_script_prompt(
            actor=request.actor,
            user_prompt=request.user_prompt,
            document_text=request.document_text,
            extra_context=request.extra_context,
        )

        raw_output = self._generate_json(prompt)
        action = parse_action_script_text(
            raw_output,
            fallback_actor=request.actor,
        )

        return PlannerResult(
            action=action,
            raw_model_output=raw_output,
            planner_backend=self.backend_name,
            warnings=[],
        )

    def replan(self, request: SafeReplanRequest) -> PlannerResult:
        prompt = build_safe_replan_prompt(
            actor=request.actor,
            original_action_json=request.original_action.model_dump(mode="json"),
            blocked_decision=request.blocked_decision,
            blocked_reason=request.blocked_reason,
            safe_alternative=request.safe_alternative,
            document_text=request.document_text,
        )

        raw_output = self._generate_json(prompt)
        action = parse_action_script_text(
            raw_output,
            fallback_actor=request.actor,
        )

        return PlannerResult(
            action=action,
            raw_model_output=raw_output,
            planner_backend=f"{self.backend_name}_safe_replan",
            warnings=["Safe replan generated by Gemini. Must be verified again."],
        )
    def _generate_json(self, prompt: str) -> str:
        """
        Generate JSON from Gemini.

        Important:
        We intentionally use Gemini JSON mode instead of passing the full
        ActionScript Pydantic schema as response_schema.

        Why:
        Pydantic models with extra="forbid" can emit additionalProperties /
        additional_properties fields. Gemini's schema subset may reject those
        fields with INVALID_ARGUMENT.

        Safety:
        The returned JSON is still validated by parse_action_script_text()
        against the real ActionScript Pydantic model after generation.
        """

        api_key = self.api_key or os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise PlannerDependencyError(
                "GEMINI_API_KEY is not configured. Use MockPlanner for local tests "
                "or set GEMINI_API_KEY for live Gemini planning."
            )

        try:
            from google import genai
            from google.genai import types
        except Exception as exc:
            raise PlannerDependencyError(
                "google-genai is not installed. Install it with: "
                "pip install google-genai"
            ) from exc

        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=self.temperature,
            ),
        )

        if not getattr(response, "text", None):
            raise RuntimeError("Gemini returned an empty response.")

        return response.text
# ---------------------------------------------------------------------------
# Local extraction helpers
# ---------------------------------------------------------------------------


def _extract_amount_usd(*texts: str) -> float:
    """
    Extract a money amount without confusing invoice IDs for amounts.

    Priority:
    1. Dollar-prefixed amount: $52,000
    2. Amount field: Amount: 52000 USD
    3. Number followed by USD
    4. Largest standalone number as last-resort fallback
    """

    combined = "\n".join(texts)

    dollar_match = re.search(
        r"\$\s*([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.\d{1,2})?",
        combined,
        flags=re.IGNORECASE,
    )
    if dollar_match:
        return float(dollar_match.group(1).replace(",", ""))

    amount_field_match = re.search(
        r"\bamount\s*[:=]?\s*\$?\s*([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.\d{1,2})?\s*(?:usd|dollars)?\b",
        combined,
        flags=re.IGNORECASE,
    )
    if amount_field_match:
        return float(amount_field_match.group(1).replace(",", ""))

    usd_match = re.search(
        r"\b([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.\d{1,2})?\s*(?:usd|dollars)\b",
        combined,
        flags=re.IGNORECASE,
    )
    if usd_match:
        return float(usd_match.group(1).replace(",", ""))

    numbers = [
        float(match.replace(",", ""))
        for match in re.findall(
            r"\b([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)\b",
            combined,
        )
    ]

    if not numbers:
        return 0.0

    return max(numbers)


def _extract_resource_id(*texts: str, default: str) -> str:
    combined = "\n".join(texts)

    patterns = [
        r"\b(invoice_[A-Za-z0-9_-]+)\b",
        r"\b(contract_[A-Za-z0-9_-]+)\b",
        r"\b(employee_records)\b",
        r"\b(vendor_update_[A-Za-z0-9_-]+)\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, combined, flags=re.IGNORECASE)
        if match:
            return match.group(1)

    return default


def _extract_email(text: str) -> str | None:
    match = re.search(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text,
    )
    return match.group(0) if match else None