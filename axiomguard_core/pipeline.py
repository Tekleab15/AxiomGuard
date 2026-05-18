"""
AxiomGuard end-to-end pipeline orchestrator.

This module connects the core runtime:

1. ActionScript from Gemini or a mock planner
2. LobsterTrapFinding from Lobster Trap or a mock trap client
3. AxiomLNN policy inference
4. Deterministic enforcement gate
5. Decision Receipt generation
6. Receipt-required simulated tool execution

Winning principle:
Gemini may plan, Lobster Trap may inspect, AxiomLNN may infer,
but only a valid ALLOW Decision Receipt can authorize execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any
import copy

from axiomguard_core.enforcer import DeterministicGate, GateThresholds
from axiomguard_core.receipts import (
    generate_decision_receipt,
    save_receipt_json,
    save_receipt_markdown,
    verify_receipt_hash,
)
from axiomguard_core.schemas import (
    ActionScript,
    AxiomLNNInference,
    Decision,
    DecisionReceipt,
    EnforcementDecision,
    LobsterTrapFinding,
    ToolResult,
)
from axiomguard_core.tools import attempt_tool_execution
from axiomguard_core.verifier import AxiomLNNVerifier, VerifierConfig

# ---------------------------------
# Pipeline configuration
# ---------------------------------

@dataclass(frozen=True)
class PipelineOptions:
    """
    Runtime options for AxiomGuard pipeline execution.
    """

    agent: str = "procurement_copilot"

    execute_tools: bool = True

    persist_receipt: bool = False
    export_markdown: bool = False
    receipt_directory: str | Path = "data/receipts/generated"

    previous_receipt_hash: str | None = None

@dataclass
@dataclass
class AxiomGuardPipelineResult:
    """
    Complete output of one AxiomGuard protected action run.

    This is the object the API, Streamlit dashboard, and red-team runner
    should use as their stable interface.
    """
    action: ActionScript
    lobstertrap_findings: LobsterTrapFinding
    lnn_inference: AxiomLNNInference
    enforcement: EnforcementDecision
    receipt: DecisionReceipt
    tool_result: ToolResult | None

    stage_timings_ms: dict[str, float] = field(default_factory=dict)

    receipt_json_path: str | None = None
    receipt_markdown_path: str | None = None
    persistence_error: str | None = None
    @property
    def final_decision(self) -> Decision:
        return self.receipt.final_decision

    @property
    def allowed_to_execute(self) -> bool:
        return self.receipt.allowed_to_execute

    @property
    def executed(self) -> bool:
        return bool(self.tool_result and self.tool_result.executed)

    @property
    def blocked_reason(self) -> str | None:
        if self.tool_result is None:
            return None
        return self.tool_result.blocked_reason

    def to_dashboard_dict(self) -> dict[str, Any]:
        """
        Dashboard-friendly summary.

        The Streamlit app can render this directly without digging through
        nested Pydantic models.
        """

        matched_formulas = [
            {
                "policy_id": formula.policy_id,
                "decision": formula.decision.value,
                "score": formula.score,
                "trace": formula.trace,
            }
            for formula in self.lnn_inference.matched_formulas
        ]

        return {
            "receipt_id": self.receipt.receipt_id,
            "receipt_hash": self.receipt.receipt_hash,
            "agent": self.receipt.agent,
            "final_decision": self.final_decision.value,
            "execution_status": self.enforcement.execution_status.value,
            "allowed_to_execute": self.allowed_to_execute,
            "executed": self.executed,
            "blocked_reason": self.blocked_reason,
            "matched_policy": self.enforcement.matched_policy,
            "reason": self.enforcement.reason,
            "safe_alternative": self.enforcement.safe_alternative,
            "action": {
                "action_id": self.action.action_id,
                "action_type": self.action.action_type.value,
                "tool_name": self.action.tool_name.value,
                "resource_id": self.action.resource_id,
                "amount_usd": self.action.amount_usd,
                "destination": self.action.destination.value,
                "recipient": self.action.recipient,
                "actor_id": self.action.actor.id,
                "actor_role": self.action.actor.role,
                "data_classes": [item.value for item in self.action.data_classes],
            },
            "lobstertrap": {
                "risk_score": self.lobstertrap_findings.risk_score,
                "prompt_injection": self.lobstertrap_findings.prompt_injection,
                "exfiltration_detected": self.lobstertrap_findings.exfiltration_detected,
                "pii_detected": self.lobstertrap_findings.pii_detected,
                "credential_detected": self.lobstertrap_findings.credential_detected,
                "risky_command_detected": self.lobstertrap_findings.risky_command_detected,
                "intent_mismatch": self.lobstertrap_findings.intent_mismatch,
                "detected_domains": self.lobstertrap_findings.detected_domains,
            },
            "lnn": {
                "allow": [
                    self.lnn_inference.allow.lower,
                    self.lnn_inference.allow.upper,
                ],
                "deny": [
                    self.lnn_inference.deny.lower,
                    self.lnn_inference.deny.upper,
                ],
                "redact": [
                    self.lnn_inference.redact.lower,
                    self.lnn_inference.redact.upper,
                ],
                "quarantine": [
                    self.lnn_inference.quarantine.lower,
                    self.lnn_inference.quarantine.upper,
                ],
                "human_review": [
                    self.lnn_inference.human_review.lower,
                    self.lnn_inference.human_review.upper,
                ],
                "rate_limit": [
                    self.lnn_inference.rate_limit.lower,
                    self.lnn_inference.rate_limit.upper,
                ],
                "contradiction_loss": self.lnn_inference.contradiction_loss,
                "matched_formulas": matched_formulas,
            },
            
            "tool_result": (
                self.tool_result.model_dump(mode="json")
                if self.tool_result is not None
                else {
                    "tool_name": self.action.tool_name.value,
                    "receipt_id": self.receipt.receipt_id,
                    "executed": False,
                    "status": "skipped_dry_run_preview",
                    "output": {},
                    "blocked_reason": (
                        "Execution skipped via pipeline preview configuration."
                    ),
                }
            ),
            "receipt_json_path": self.receipt_json_path,
            "receipt_markdown_path": self.receipt_markdown_path,
            "persistence_error": self.persistence_error,
            "stage_timings_ms": self.stage_timings_ms,
        }
# -----------------------------------
# Pipeline implementation
# -----------------------------------

class AxiomGuardPipeline:
    """
    End-to-end AxiomGuard runtime.

    This is the main product engine. Every app surface should call this:
    - Streamlit dashboard
    - FastAPI backend
    - red-team runner
    - demo scripts
    """

    def __init__(
        self,
        *,
        verifier: AxiomLNNVerifier | None = None,
        gate: DeterministicGate | None = None,
    ) -> None:
        self.verifier = verifier or AxiomLNNVerifier()
        self.gate = gate or DeterministicGate()

    def run(
        self,
        *,
        action: ActionScript,
        lobstertrap_findings: LobsterTrapFinding,
        options: PipelineOptions | None = None,
    ) -> AxiomGuardPipelineResult:
        """
        Run one proposed action through the full AxiomGuard control plane.

        Security hardening:
        - Deep-copy inbound objects at the boundary to prevent mutation leaks.
        - Continue core enforcement even if receipt persistence fails.
        - Keep dry-run execution explicit for dashboard clarity.
        """

        frozen_action = action.model_copy(deep=True)
        frozen_findings = lobstertrap_findings.model_copy(deep=True)
        frozen_options = copy.deepcopy(options or PipelineOptions())

        stage_timings: dict[str, float] = {}
        persistence_error: str | None = None

        total_start = perf_counter()

        verify_start = perf_counter()
        inference = self.verifier.verify(
            action=frozen_action,
            trap=frozen_findings,
        )
        stage_timings["verify"] = _elapsed_ms(verify_start)

        enforce_start = perf_counter()
        enforcement = self.gate.enforce(
            action=frozen_action,
            trap=frozen_findings,
            inference=inference,
        )
        stage_timings["enforce"] = _elapsed_ms(enforce_start)

        receipt_start = perf_counter()
        receipt = generate_decision_receipt(
            action=frozen_action,
            lobstertrap_findings=frozen_findings,
            lnn_inference=inference,
            enforcement=enforcement,
            agent=frozen_options.agent,
            previous_receipt_hash=frozen_options.previous_receipt_hash,
        )
        stage_timings["receipt"] = _elapsed_ms(receipt_start)

        if not verify_receipt_hash(receipt):
            raise RuntimeError(
                f"Generated receipt {receipt.receipt_id} failed hash verification."
            )

        json_path: str | None = None
        markdown_path: str | None = None

        persist_start = perf_counter()

        try:
            if frozen_options.persist_receipt:
                saved_json = save_receipt_json(
                    receipt,
                    directory=frozen_options.receipt_directory,
                )
                json_path = str(saved_json)

            if frozen_options.export_markdown:
                saved_markdown = save_receipt_markdown(
                    receipt,
                    directory=frozen_options.receipt_directory,
                )
                markdown_path = str(saved_markdown)

        except Exception as exc:
            persistence_error = (
                f"{exc.__class__.__name__}: {exc}"
            )
            stage_timings["persist_error"] = 1.0

        stage_timings["persist"] = _elapsed_ms(persist_start)

        execute_start = perf_counter()
        tool_result = (
            attempt_tool_execution(receipt)
            if frozen_options.execute_tools
            else None
        )
        stage_timings["execute"] = _elapsed_ms(execute_start)

        stage_timings["total"] = _elapsed_ms(total_start)

        return AxiomGuardPipelineResult(
            action=frozen_action,
            lobstertrap_findings=frozen_findings,
            lnn_inference=inference,
            enforcement=enforcement,
            receipt=receipt,
            tool_result=tool_result,
            stage_timings_ms=stage_timings,
            receipt_json_path=json_path,
            receipt_markdown_path=markdown_path,
            persistence_error=persistence_error,
        )
# -----------------------------------
# Convenience functions
# -----------------------------------

def run_axiomguard_pipeline(
    *,
    action: ActionScript,
    lobstertrap_findings: LobsterTrapFinding,
    options: PipelineOptions | None = None,
    verifier_config: VerifierConfig | None = None,
    gate_thresholds: GateThresholds | None = None,
) -> AxiomGuardPipelineResult:
    """
    Convenience function for scripts, tests, and dashboard callbacks.
    """

    pipeline = AxiomGuardPipeline(
        verifier=AxiomLNNVerifier(config=verifier_config),
        gate=DeterministicGate(thresholds=gate_thresholds),
    )

    return pipeline.run(
        action=action,
        lobstertrap_findings=lobstertrap_findings,
        options=options,
    )

def run_pipeline_no_execution(
    *,
    action: ActionScript,
    lobstertrap_findings: LobsterTrapFinding,
    agent: str = "procurement_copilot",
) -> AxiomGuardPipelineResult:
    """
    Run the pipeline without executing tools.

    Useful for:
    - dry-run governance previews
    - receipt-only audits
    - UI previews before pressing "Execute"
    """

    return run_axiomguard_pipeline(
        action=action,
        lobstertrap_findings=lobstertrap_findings,
        options=PipelineOptions(
            agent=agent,
            execute_tools=False,
        ),
    )
# -------------------------------
# Helpers
# -------------------------------

def _elapsed_ms(start: float) -> float:
    return round((perf_counter() - start) * 1000.0, 3)