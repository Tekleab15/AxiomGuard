"""
Decision Receipt generation for AxiomGuard.
A Decision Receipt is the audit artifact for every proposed agent action.

It records:
- who requested the action
- what Gemini proposed
- what Lobster Trap detected
- what AxiomLNN inferred
- what the deterministic gate decided
- which policy matched
- why the action was allowed or blocked
- what safe alternative exists

Security principle:
No Decision Receipt, no execution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from axiomguard_core.schemas import (
    ActionScript,
    AxiomLNNInference,
    Decision,
    DecisionReceipt,
    EnforcementDecision,
    LobsterTrapFinding,
)

# --------------------------
# Receipt IDs
# --------------------------

def generate_receipt_id(prefix: str = "AXG") -> str:
    """
    Generate a readable receipt ID for demos and audit logs.

    Example:
        AXG-20260518-A1B2C3D4
    """
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_part = uuid.uuid4().hex[:8].upper()
    return f"{prefix}-{date_part}-{random_part}"

def sanitize_receipt_id(receipt_id: str) -> str:
    """
    Convert a receipt ID into a safe filename segment.
    """
    return re.sub(r"[^A-Za-z0-9_.-]", "_", receipt_id)


# --------------------------
# Hashing
# --------------------------

def _canonical_receipt_payload(receipt: DecisionReceipt) -> dict[str, Any]:
    """
    Return the stable payload used for hashing.

    The receipt hash itself is excluded so the hash does not recursively hash
    its own value. The previous_receipt_hash is included, which allows optional
    hash-linked audit chains.
    """
    return receipt.model_dump(
        mode="json",
        exclude={"receipt_hash"},
    )

def canonical_receipt_json(receipt: DecisionReceipt) -> str:
    """
    Produce stable canonical JSON for receipt hashing.
    """
    payload = _canonical_receipt_payload(receipt)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

def compute_receipt_hash(receipt: DecisionReceipt) -> str:
    """
    Compute a SHA-256 hash for a Decision Receipt.
    Returns:
        sha256:<hex>
    """
    canonical_json = canonical_receipt_json(receipt)
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"

def verify_receipt_hash(receipt: DecisionReceipt) -> bool:
    """
    Verify that the receipt hash matches the receipt payload.
    Returns False if the receipt has no hash.
    """
    if not receipt.receipt_hash:
        return False

    expected_hash = compute_receipt_hash(receipt)
    return hmac.compare_digest(receipt.receipt_hash, expected_hash)


# ----------------------------
# Receipt generation
# ----------------------------

def generate_decision_receipt(
    *,
    action: ActionScript,
    lobstertrap_findings: LobsterTrapFinding,
    lnn_inference: AxiomLNNInference,
    enforcement: EnforcementDecision,
    agent: str = "procurement_copilot",
    receipt_id: str | None = None,
    previous_receipt_hash: str | None = None,
    timestamp: datetime | None = None,
) -> DecisionReceipt:
    """
    Generate a hash-attached Decision Receipt.

    This function should be called after the deterministic gate returns an
    EnforcementDecision and before any tool execution is attempted.
    """

    receipt = DecisionReceipt(
        receipt_id=receipt_id or generate_receipt_id(),
        timestamp=timestamp or datetime.now(timezone.utc),
        agent=agent,
        action=action,
        lobstertrap_findings=lobstertrap_findings,
        lnn_inference=lnn_inference,
        enforcement=enforcement,
        previous_receipt_hash=previous_receipt_hash,
    )

    receipt_hash = compute_receipt_hash(receipt)
    return receipt.model_copy(update={"receipt_hash": receipt_hash})

# ----------------------------
# Persistence
# ----------------------------

def receipt_to_dict(receipt: DecisionReceipt) -> dict[str, Any]:
    """
    Convert a receipt to JSON-serializable dictionary form.
    """
    return receipt.model_dump(mode="json")

def receipt_to_json(receipt: DecisionReceipt, *, indent: int = 2) -> str:
    """
    Convert a receipt to pretty JSON for storage or dashboard display.
    """

    return json.dumps(
        receipt_to_dict(receipt),
        indent=indent,
        ensure_ascii=False,
    )

def save_receipt_json(
    receipt: DecisionReceipt,
    directory: str | Path = "data/receipts/generated",
) -> Path:
    """
    Save a receipt as JSON.

    Returns:
        Path to the saved receipt.
    """

    output_dir = Path(directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{sanitize_receipt_id(receipt.receipt_id)}.json"
    output_path = output_dir / filename

    output_path.write_text(
        receipt_to_json(receipt),
        encoding="utf-8",
    )

    return output_path

def load_receipt_json(path: str | Path) -> DecisionReceipt:
    """
    Load a Decision Receipt from JSON.
    """

    input_path = Path(path)
    return DecisionReceipt.model_validate_json(
        input_path.read_text(encoding="utf-8")
    )

def list_receipt_files(
    directory: str | Path = "data/receipts/generated",
) -> list[Path]:
    """
    List stored receipt JSON files.
    """
    input_dir = Path(directory)
    if not input_dir.exists():
        return []

    return sorted(input_dir.glob("*.json"))

# ----------------------------
# Human-readable export
# ----------------------------

def export_receipt_markdown(receipt: DecisionReceipt) -> str:
    """
    Export a CISO-readable / judge-readable receipt summary.

    This is useful for:
    - Streamlit display
    - PDF export later
    - audit report generation
    - demo screenshots
    """

    action = receipt.action
    trap = receipt.lobstertrap_findings
    inference = receipt.lnn_inference
    enforcement = receipt.enforcement

    matched_formulas = "\n".join(
        [
            (
                f"- `{formula.policy_id}` "
                f"({formula.decision.value}, score={formula.score:.2f}): "
                f"{formula.trace}"
            )
            for formula in inference.matched_formulas
        ]
    )

    if not matched_formulas:
        matched_formulas = "- No explicit formula trace was attached."

    sensitive_data = ", ".join([item.value for item in action.data_classes])
    risk_signals = ", ".join([item.value for item in action.risk_signals]) or "none"

    safe_alternative = enforcement.safe_alternative or "No safe alternative required."

    markdown = f"""# Decision Receipt: {receipt.receipt_id}

## Final Decision

**Decision:** `{receipt.final_decision.value}`  
**Execution status:** `{enforcement.execution_status.value}`  
**Allowed to execute:** `{receipt.allowed_to_execute}`  
**Matched policy:** `{enforcement.matched_policy}`  

## Reason

{enforcement.reason}

## Actor

| Field | Value |
|---|---|
| Actor ID | `{action.actor.id}` |
| Role | `{action.actor.role}` |
| Department | `{action.actor.department}` |
| Approval limit | `${action.actor.approval_limit_usd:,.2f}` |

## Proposed Action

| Field | Value |
|---|---|
| Action ID | `{action.action_id}` |
| Declared intent | {action.declared_intent} |
| Detected intent | {action.detected_intent} |
| Action type | `{action.action_type.value}` |
| Tool | `{action.tool_name.value}` |
| Resource | `{action.resource_id}` |
| Amount | `{action.amount_usd}` |
| Destination | `{action.destination.value}` |
| Recipient | `{action.recipient or "none"}` |
| Data classes | `{sensitive_data}` |
| Risk signals | `{risk_signals}` |

## Lobster Trap Findings

| Signal | Value |
|---|---|
| Prompt injection | `{trap.prompt_injection}` |
| Exfiltration detected | `{trap.exfiltration_detected}` |
| PII detected | `{trap.pii_detected}` |
| Credential detected | `{trap.credential_detected}` |
| Risky command detected | `{trap.risky_command_detected}` |
| Intent mismatch | `{trap.intent_mismatch}` |
| Risk score | `{trap.risk_score}` |
| Detected domains | `{", ".join(trap.detected_domains) or "none"}` |

## AxiomLNN Inference

| Decision node | Truth lower | Truth upper |
|---|---:|---:|
| Allow | {inference.allow.lower:.2f} | {inference.allow.upper:.2f} |
| Deny | {inference.deny.lower:.2f} | {inference.deny.upper:.2f} |
| Redact | {inference.redact.lower:.2f} | {inference.redact.upper:.2f} |
| Quarantine | {inference.quarantine.lower:.2f} | {inference.quarantine.upper:.2f} |
| Human review | {inference.human_review.lower:.2f} | {inference.human_review.upper:.2f} |
| Rate limit | {inference.rate_limit.lower:.2f} | {inference.rate_limit.upper:.2f} |

**Contradiction loss:** `{inference.contradiction_loss:.2f}`

## Matched Formula Trace

{matched_formulas}

## Safe Alternative

{safe_alternative}

## Audit Integrity

| Field | Value |
|---|---|
| Receipt hash | `{receipt.receipt_hash}` |
| Previous receipt hash | `{receipt.previous_receipt_hash or "none"}` |
| Timestamp | `{receipt.timestamp.isoformat()}` |
| Version | `{receipt.version}` |
"""
    return markdown

def save_receipt_markdown(
    receipt: DecisionReceipt,
    directory: str | Path = "data/receipts/generated",
) -> Path:
    """
    Save a human-readable Markdown version of a receipt.
    """

    output_dir = Path(directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{sanitize_receipt_id(receipt.receipt_id)}.md"
    output_path = output_dir / filename

    output_path.write_text(
        export_receipt_markdown(receipt),
        encoding="utf-8",
    )

    return output_path

# ----------------------------
# Decision helpers
# ----------------------------

def assert_receipt_allows_execution(receipt: DecisionReceipt) -> None:
    """
    Raise PermissionError unless the receipt authorizes execution.

    This will be used by the simulated tool executor in a later component.
    """

    if not verify_receipt_hash(receipt):
        raise PermissionError(
            f"Receipt {receipt.receipt_id} failed hash verification."
        )

    if receipt.final_decision != Decision.ALLOW:
        raise PermissionError(
            f"Receipt {receipt.receipt_id} does not authorize execution. "
            f"Final decision is {receipt.final_decision.value}."
        )