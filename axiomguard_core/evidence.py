"""
Evidence and Compliance layer for AxiomGuard.

This module translates the validated AxiomGuard backend results into
empirical, enterprise-readable compliance evidence:

- OWASP Top 10 LLM Risk Mapping
- Executive Security Summary
- Auditor-Ready CISO Markdown Report
- Receipt Chain Timeline
- Tamper-Evidence Simulation

Design Principle:
Report strictly on measured metrics. Do not make universal security guarantees.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from axiomguard_core.receipts import load_receipt_json, verify_receipt_hash
from axiomguard_core.redteam import RedTeamSuiteResult, suite_to_markdown
from axiomguard_core.schemas import DecisionReceipt


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 Risk Mapping
# ---------------------------------------------------------------------------

TAG_TO_OWASP: dict[str, list[str]] = {
    "prompt_injection": ["LLM01:2025 Prompt Injection"],
    "intent_mismatch": ["LLM01:2025 Prompt Injection"],
    "pii": ["LLM02:2025 Sensitive Information Disclosure"],
    "salary_data": ["LLM02:2025 Sensitive Information Disclosure"],
    "credential": ["LLM02:2025 Sensitive Information Disclosure"],
    "secret": ["LLM02:2025 Sensitive Information Disclosure"],
    "vendor_bank_details": ["LLM02:2025 Sensitive Information Disclosure"],
    "external_email": ["LLM06:2025 Excessive Agency"],
    "exfiltration": [
        "LLM02:2025 Sensitive Information Disclosure",
        "LLM06:2025 Excessive Agency",
    ],
    "unauthorized_action": ["LLM06:2025 Excessive Agency"],
    "high_value_transaction": ["LLM06:2025 Excessive Agency"],
    "finance": ["LLM06:2025 Excessive Agency"],
    "redaction": ["LLM05:2025 Improper Output Handling"],
}

OWASP_DESCRIPTIONS: dict[str, str] = {
    "LLM01:2025 Prompt Injection": (
        "Adversarial inputs intended to override system instructions or alter agent behavior."
    ),
    "LLM02:2025 Sensitive Information Disclosure": (
        "Unauthorized exposure of PII, credentials, financial details, or proprietary secrets."
    ),
    "LLM05:2025 Improper Output Handling": (
        "Failure to validate, sanitize, or redact model outputs before downstream execution."
    ),
    "LLM06:2025 Excessive Agency": (
        "Agent possesses over-privileged access to actions or tools that can cause business impact."
    ),
}


# ---------------------------------------------------------------------------
# Receipt Chain Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReceiptChainItem:
    receipt_id: str
    timestamp: str
    decision: str
    matched_policy: str
    receipt_hash: str | None
    previous_receipt_hash: str | None
    hash_valid: bool
    action_type: str
    tool_name: str
    resource_id: str
    actor_role: str
    reason: str


# ---------------------------------------------------------------------------
# OWASP / Executive Metric Calculations
# ---------------------------------------------------------------------------

def map_tags_to_owasp(tags: list[str]) -> list[str]:
    """Map red-team scenario tags to OWASP LLM risk categories."""
    risks: set[str] = set()

    for tag in tags:
        risks.update(TAG_TO_OWASP.get(tag, []))

    return sorted(risks)


def calculate_owasp_coverage(suite: RedTeamSuiteResult) -> dict[str, Any]:
    """Calculate aggregate OWASP vulnerability coverage from red-team results."""
    counter: Counter[str] = Counter()
    scenario_map: dict[str, list[str]] = {}

    for result in suite.results:
        risks = map_tags_to_owasp(result.tags)
        scenario_map[result.scenario_id] = risks
        counter.update(risks)

    return {
        "coverage": dict(counter),
        "scenario_map": scenario_map,
        "descriptions": OWASP_DESCRIPTIONS,
    }


def generate_executive_summary(suite: RedTeamSuiteResult) -> dict[str, Any]:
    """
    Generate a precise, non-exaggerated executive evidence summary.
    """
    metrics = suite.metrics
    owasp = calculate_owasp_coverage(suite)

    top_policies = sorted(
        metrics.matched_policies.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    top_decisions = sorted(
        metrics.decisions.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    return {
        "headline": (
            f"AxiomGuard achieved a {metrics.risk_reduction_percent:.2f}% "
            "reduction in unsafe executions across covered red-team scenarios."
        ),
        "disclaimer": (
            "Empirical results apply strictly to the evaluated scenario fixtures. "
            "This does not represent a universal security guarantee."
        ),
        "scenarios_tested": metrics.scenarios_tested,
        "baseline_unsafe_executions": metrics.baseline_unsafe_executions,
        "axiomguard_unsafe_executions": metrics.axiomguard_unsafe_executions,
        "unsafe_executions_prevented": metrics.unsafe_executions_prevented,
        "risk_reduction_percent": metrics.risk_reduction_percent,
        "decision_receipts_generated": metrics.decision_receipts_generated,
        "pass_rate_percent": metrics.pass_rate_percent,
        "average_policy_confidence": metrics.average_policy_confidence,
        "average_contradiction_loss": metrics.average_contradiction_loss,
        "top_policies": top_policies,
        "top_decisions": top_decisions,
        "owasp_coverage": owasp,
    }


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_judge_report_markdown(suite: RedTeamSuiteResult) -> str:
    """
    Generate a CISO-readable compliance report.
    Presents data empirically without marketing exaggeration.
    """
    summary = generate_executive_summary(suite)
    owasp = summary["owasp_coverage"]

    owasp_rows = []
    for risk, count in sorted(owasp["coverage"].items()):
        description = owasp["descriptions"].get(risk, "")
        owasp_rows.append(f"| {risk} | {count} | {description} |")

    if not owasp_rows:
        owasp_rows.append("| No mapped OWASP risks | 0 | No mapped coverage. |")

    scenario_rows = []
    for result in suite.results:
        scenario_risks = ", ".join(owasp["scenario_map"].get(result.scenario_id, []))
        scenario_rows.append(
            "| "
            f"{result.scenario_id} | "
            f"{result.scenario_name} | "
            f"{result.actual_axiomguard_decision.value} | "
            f"{result.matched_policy} | "
            f"{result.tool_executed} | "
            f"{result.passed} | "
            f"{scenario_risks or 'none'} |"
        )

    return f"""# AxiomGuard CISO Compliance Evidence Pack

## Executive Summary

**{summary["headline"]}**

> **Technical Disclaimer:** {summary["disclaimer"]}

| Metric | Measured Value |
|---|---:|
| Scenarios Tested | {summary["scenarios_tested"]} |
| Baseline Unsafe Executions | {summary["baseline_unsafe_executions"]} |
| AxiomGuard Unsafe Executions | {summary["axiomguard_unsafe_executions"]} |
| Unsafe Executions Prevented | {summary["unsafe_executions_prevented"]} |
| Empirical Risk Reduction | {summary["risk_reduction_percent"]:.2f}% |
| Cryptographic Receipts Generated | {summary["decision_receipts_generated"]} |
| Suite Pass Rate | {summary["pass_rate_percent"]:.2f}% |
| LNN Average Contradiction Loss | {summary["average_contradiction_loss"]:.2f} |

## OWASP LLM Risk Coverage

| OWASP Vulnerability Category | Triggered Count | Enterprise Threat Context |
|---|---:|---|
{chr(10).join(owasp_rows)}

## Scenario Execution Evidence

| ID | Scenario | Enforcement Gate Decision | Matched Policy | Tool Executed | Status | OWASP Mapping |
|---|---|---|---|---:|---:|---|
{chr(10).join(scenario_rows)}

## Baseline vs. Protected Replay Data

{suite_to_markdown(suite)}

## System Architecture Integrity

AxiomGuard enforces the following strict runtime isolation sequence:

1. **Gemini / MockPlanner** -> Proposes ActionScript JSON.
2. **Lobster Trap** -> Extracts risk metadata via deep prompt inspection.
3. **AxiomLNN** -> Computes truth-bound policy inference intervals.
4. **Deterministic Gate** -> Enforces the final authorization decision.
5. **Decision Receipt** -> Seals the transaction with a tamper-evident SHA-256 hash over canonical JSON.
6. **Tool Executor** -> Executes only if a valid ALLOW receipt is presented.

## Compliance Claim

AxiomGuard does not claim universal security. It provides measured risk reduction
on defined enterprise red-team scenarios and produces tamper-evident Decision
Receipts for each attempted action.
"""


def save_judge_report(
    suite: RedTeamSuiteResult,
    path: str | Path = "data/redteam/AxiomGuard_CISO_Compliance_Report.md",
) -> Path:
    """Save the auditor-ready CISO report as Markdown."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        generate_judge_report_markdown(suite),
        encoding="utf-8",
    )
    return output_path


def save_owasp_coverage(
    suite: RedTeamSuiteResult,
    path: str | Path = "data/redteam/owasp_coverage.json",
) -> Path:
    """Save OWASP coverage as machine-readable JSON."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(calculate_owasp_coverage(suite), indent=2),
        encoding="utf-8",
    )
    return output_path


# ---------------------------------------------------------------------------
# Receipt Chain Timeline
# ---------------------------------------------------------------------------

def build_receipt_chain(
    directory: str | Path = "data/receipts/generated",
) -> list[dict[str, Any]]:
    """
    Build a receipt-chain timeline from saved Decision Receipt JSON files.
    """

    directory = Path(directory)

    if not directory.exists():
        return []

    receipts: list[DecisionReceipt] = []

    for path in sorted(directory.glob("*.json")):
        try:
            receipts.append(load_receipt_json(path))
        except Exception:
            continue

    receipts.sort(key=lambda receipt: receipt.timestamp)

    return [
        _receipt_to_chain_item(receipt).__dict__
        for receipt in receipts
    ]


def _receipt_to_chain_item(receipt: DecisionReceipt) -> ReceiptChainItem:
    return ReceiptChainItem(
        receipt_id=receipt.receipt_id,
        timestamp=receipt.timestamp.isoformat(),
        decision=receipt.final_decision.value,
        matched_policy=receipt.enforcement.matched_policy,
        receipt_hash=receipt.receipt_hash,
        previous_receipt_hash=receipt.previous_receipt_hash,
        hash_valid=verify_receipt_hash(receipt),
        action_type=receipt.action.action_type.value,
        tool_name=receipt.action.tool_name.value,
        resource_id=receipt.action.resource_id,
        actor_role=receipt.action.actor.role,
        reason=receipt.enforcement.reason,
    )


# ---------------------------------------------------------------------------
# Tamper Evidence Helper
# ---------------------------------------------------------------------------

def simulate_receipt_tamper(receipt: DecisionReceipt) -> dict[str, Any]:
    """
    Simulate malicious insider tampering against a Decision Receipt.

    The function modifies the enforcement reason in memory and verifies that
    the original receipt hash no longer matches the modified payload.
    """

    tampered_enforcement = receipt.enforcement.model_copy(
        update={
            "reason": (
                receipt.enforcement.reason
                + " [TAMPERED: malicious insider modified this record.]"
            )
        }
    )

    tampered_receipt = receipt.model_copy(
        update={"enforcement": tampered_enforcement}
    )

    return {
        "receipt_id": receipt.receipt_id,
        "original_hash": receipt.receipt_hash,
        "tampered_hash_valid": verify_receipt_hash(tampered_receipt),
        "tampered_field": "enforcement.reason",
        "security_result": (
            "tamper_detected"
            if not verify_receipt_hash(tampered_receipt)
            else "tamper_not_detected"
        ),
    }