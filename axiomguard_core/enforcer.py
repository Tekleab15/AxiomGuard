"""
Deterministic execution gate for AxiomGuard.
This module is the runtime circuit breaker.

It converts:
- Gemini-generated ActionScript
- Lobster Trap inspection metadata
- AxiomLNN truth-bound inference

into a final enforceable decision:
ALLOW, DENY, REDACT, QUARANTINE, HUMAN_REVIEW, or RATE_LIMIT.

Security principle:
The LLM may propose actions, but the deterministic gate decides whether execution is allowed.
"""

from __future__ import annotations

from dataclasses import dataclass

from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    AxiomLNNInference,
    Decision,
    DestinationType,
    EnforcementDecision,
    ExecutionStatus,
    LobsterTrapFinding,
    MatchedFormula,
    ToolName,
)

# --------------------------------------
# Configuration
# ---------------------------------------

@dataclass(frozen=True)
class GateThresholds:
    """
    Thresholds used by the deterministic gate.

    AxiomGuard uses 0.0-1.0 truth bounds for AxiomLNN scores
    and 0-100 risk scores for normalized Lobster Trap findings.
    """

    quarantine: float = 0.80
    deny: float = 0.80
    human_review: float = 0.70
    redact: float = 0.70
    rate_limit: float = 0.80
    allow: float = 0.80

    allow_risk_ceiling: float = 50.0
    trap_quarantine_risk: float = 90.0
    trap_human_review_risk: float = 75.0
    contradiction_review_threshold: float = 0.25

EXPECTED_TOOL_BY_ACTION: dict[ActionType, set[ToolName]] = {
    ActionType.SUMMARIZE_INVOICE: {ToolName.DOCS_SUMMARIZE},
    ActionType.SUMMARIZE_CONTRACT: {ToolName.DOCS_SUMMARIZE},
    ActionType.APPROVE_INVOICE: {ToolName.ERP_APPROVE_INVOICE},
    ActionType.SEND_EMAIL: {ToolName.EMAIL_SEND},
    ActionType.CREATE_APPROVAL_PACKET: {ToolName.WORKFLOW_CREATE_APPROVAL_PACKET},
    ActionType.CREATE_REDACTED_REPORT: {ToolName.REPORTS_CREATE_REDACTED_REPORT},
}

#-----------------------------------
# Gate implementation
# ---------------------------------

class DeterministicGate:
    """
    AxiomGuard's final pre-execution policy gate.
    It has two stages:
    1. Hard boundary checks:
       These are non-negotiable enterprise controls. They override all LNN scores.
    2. AxiomLNN priority evaluation:
       QUARANTINE > DENY > HUMAN_REVIEW > REDACT > RATE_LIMIT > ALLOW

    This design makes the demo reliable even if the planner or LNN layer
    produces incomplete or conflicting outputs.
    """

    def __init__(self, thresholds: GateThresholds | None = None) -> None:
        self.thresholds = thresholds or GateThresholds()

    def enforce(
        self,
        action: ActionScript,
        trap: LobsterTrapFinding,
        inference: AxiomLNNInference,
    ) -> EnforcementDecision:
        """
        Return the final enforceable decision for a proposed action.
        """

        hard_decision = self._evaluate_hard_boundaries(action, trap, inference)
        if hard_decision is not None:
            return hard_decision

        return self._evaluate_lnn_priority(action, trap, inference)

    # --------------------------------------
    # Stage 1: hard enterprise boundaries
    # -------------------------------------

    def _evaluate_hard_boundaries(
        self,
        action: ActionScript,
        trap: LobsterTrapFinding,
        inference: AxiomLNNInference,
    ) -> EnforcementDecision | None:
        """
        Hard checks that must override model or LNN optimism.
        """

        if not self._tool_matches_action(action):
            return self._decision(
                decision=Decision.DENY,
                reason=(
                    f"Tool/action mismatch. Action '{action.action_type.value}' "
                    f"cannot use tool '{action.tool_name.value}'."
                ),
                matched_policy="TOOL-001",
                safe_alternative="Regenerate the Action Script with an approved tool for the requested action.",
            )

        if trap.prompt_injection or trap.exfiltration_detected:
            return self._decision(
                decision=Decision.QUARANTINE,
                reason="Lobster Trap detected prompt injection or exfiltration behavior.",
                matched_policy="SEC-003",
                safe_alternative="Quarantine the request and route it to security review.",
            )

        if trap.risk_score >= self.thresholds.trap_quarantine_risk:
            return self._decision(
                decision=Decision.QUARANTINE,
                reason=(
                    f"Lobster Trap risk score is {trap.risk_score:.1f}, "
                    f"which exceeds the quarantine threshold of "
                    f"{self.thresholds.trap_quarantine_risk:.1f}."
                ),
                matched_policy="SEC-004",
                safe_alternative="Quarantine the request and review extracted risk metadata.",
            )

        if trap.credential_detected:
            return self._decision(
                decision=Decision.DENY,
                reason="Credential-like content was detected in the prompt or response.",
                matched_policy="DATA-003",
                safe_alternative="Remove credentials and retry with a sanitized request.",
            )

        if trap.risky_command_detected:
            return self._decision(
                decision=Decision.DENY,
                reason="Risky command or unsafe operational instruction was detected.",
                matched_policy="SEC-005",
                safe_alternative="Rewrite the request as a read-only or human-reviewed workflow.",
            )

        if action.is_external_transfer and action.touches_sensitive_data:
            return self._decision(
                decision=Decision.DENY,
                reason="Sensitive data cannot be transferred to an external destination.",
                matched_policy="DATA-002",
                safe_alternative="Create a redacted internal report or route the request to human review.",
            )

        if action.is_high_value_transaction:
            return self._decision(
                decision=Decision.HUMAN_REVIEW,
                reason=(
                    f"Invoice amount ${action.amount_usd:,.2f} exceeds actor approval "
                    f"limit ${action.actor.approval_limit_usd:,.2f}."
                ),
                matched_policy="FIN-001",
                safe_alternative="Create an approval packet and route it to a finance manager.",
            )

        if trap.intent_mismatch:
            return self._decision(
                decision=Decision.HUMAN_REVIEW,
                reason="Declared intent and detected intent do not match.",
                matched_policy="INTENT-001",
                safe_alternative="Ask the user to clarify intent or route to human review.",
            )

        if trap.risk_score >= self.thresholds.trap_human_review_risk:
            return self._decision(
                decision=Decision.HUMAN_REVIEW,
                reason=(
                    f"Lobster Trap risk score is {trap.risk_score:.1f}, "
                    f"which exceeds the human-review threshold of "
                    f"{self.thresholds.trap_human_review_risk:.1f}."
                ),
                matched_policy="RISK-001",
                safe_alternative="Route to human review before allowing any tool execution.",
            )

        if inference.contradiction_loss >= self.thresholds.contradiction_review_threshold:
            return self._decision(
                decision=Decision.HUMAN_REVIEW,
                reason=(
                    f"AxiomLNN contradiction loss is {inference.contradiction_loss:.2f}, "
                    "indicating conflicting policy signals."
                ),
                matched_policy="LNN-001",
                safe_alternative="Route to human review because policy signals conflict.",
            )

        return None

    # -------------------------------------
    # Stage 2: LNN priority order
    # -------------------------------------

    def _evaluate_lnn_priority(
        self,
        action: ActionScript,
        trap: LobsterTrapFinding,
        inference: AxiomLNNInference,
    ) -> EnforcementDecision:
        """
        Apply the core AxiomGuard priority matrix:

        QUARANTINE > DENY > HUMAN_REVIEW > REDACT > RATE_LIMIT > ALLOW
        """

        if inference.score_for(Decision.QUARANTINE) >= self.thresholds.quarantine:
            return self._decision_from_inference(
                decision=Decision.QUARANTINE,
                inference=inference,
                fallback_policy="SEC-003",
                fallback_reason="AxiomLNN inferred quarantine with high confidence.",
                safe_alternative="Quarantine the request and route it to security review.",
            )

        if inference.score_for(Decision.DENY) >= self.thresholds.deny:
            return self._decision_from_inference(
                decision=Decision.DENY,
                inference=inference,
                fallback_policy="DATA-002",
                fallback_reason="AxiomLNN inferred denial with high confidence.",
                safe_alternative="Modify the request to remove unsafe data, destination, or tool usage.",
            )

        if inference.score_for(Decision.HUMAN_REVIEW) >= self.thresholds.human_review:
            return self._decision_from_inference(
                decision=Decision.HUMAN_REVIEW,
                inference=inference,
                fallback_policy="REVIEW-001",
                fallback_reason="AxiomLNN inferred that human review is required.",
                safe_alternative="Route the action to an authorized reviewer.",
            )

        if inference.score_for(Decision.REDACT) >= self.thresholds.redact:
            return self._decision_from_inference(
                decision=Decision.REDACT,
                inference=inference,
                fallback_policy="DATA-004",
                fallback_reason="AxiomLNN inferred that redaction is required.",
                safe_alternative="Redact sensitive fields and resubmit the action for verification.",
            )

        if inference.score_for(Decision.RATE_LIMIT) >= self.thresholds.rate_limit:
            return self._decision_from_inference(
                decision=Decision.RATE_LIMIT,
                inference=inference,
                fallback_policy="RATE-001",
                fallback_reason="AxiomLNN inferred that rate limiting is required.",
                safe_alternative="Retry later or reduce request frequency.",
            )

        if (
            inference.score_for(Decision.ALLOW) >= self.thresholds.allow
            and trap.risk_score < self.thresholds.allow_risk_ceiling
        ):
            return self._decision_from_inference(
                decision=Decision.ALLOW,
                inference=inference,
                fallback_policy="ALLOW-001",
                fallback_reason="AxiomLNN inferred allow and Lobster Trap risk is below the allow ceiling.",
                safe_alternative=None,
            )

        return self._decision(
            decision=Decision.HUMAN_REVIEW,
            reason="Insufficient confidence to allow execution safely.",
            matched_policy="DEFAULT-REVIEW",
            safe_alternative="Route to human review because the action did not meet the allow threshold.",
        )

    # ----------------------------------
    # Helpers
    # ---------------------------------

    def _tool_matches_action(self, action: ActionScript) -> bool:
        expected_tools = EXPECTED_TOOL_BY_ACTION.get(action.action_type, set())
        return action.tool_name in expected_tools

    def _decision_from_inference(
        self,
        decision: Decision,
        inference: AxiomLNNInference,
        fallback_policy: str,
        fallback_reason: str,
        safe_alternative: str | None,
    ) -> EnforcementDecision:
        matched_formula = self._best_formula_for_decision(inference, decision)

        if matched_formula is not None:
            return self._decision(
                decision=decision,
                reason=matched_formula.trace,
                matched_policy=matched_formula.policy_id,
                safe_alternative=safe_alternative,
            )

        return self._decision(
            decision=decision,
            reason=fallback_reason,
            matched_policy=fallback_policy,
            safe_alternative=safe_alternative,
        )

    @staticmethod
    def _best_formula_for_decision(
        inference: AxiomLNNInference,
        decision: Decision,
    ) -> MatchedFormula | None:
        candidates = [
            formula
            for formula in inference.matched_formulas
            if formula.decision == decision
        ]

        if not candidates:
            return None

        return max(candidates, key=lambda formula: formula.score)

    def _decision(
        self,
        decision: Decision,
        reason: str,
        matched_policy: str,
        safe_alternative: str | None = None,
    ) -> EnforcementDecision:
        return EnforcementDecision(
            decision=decision,
            reason=reason,
            matched_policy=matched_policy,
            safe_alternative=safe_alternative,
            execution_status=self._execution_status_for(decision),
        )

    @staticmethod
    def _execution_status_for(decision: Decision) -> ExecutionStatus:
        if decision == Decision.ALLOW:
            # The gate authorizes execution, but the tool has not executed yet.
            # The later tool executor will update the final ToolResult.
            return ExecutionStatus.NOT_EXECUTED

        if decision == Decision.DENY:
            return ExecutionStatus.BLOCKED_DENIED

        if decision == Decision.QUARANTINE:
            return ExecutionStatus.BLOCKED_QUARANTINED

        if decision == Decision.HUMAN_REVIEW:
            return ExecutionStatus.BLOCKED_PENDING_REVIEW

        if decision == Decision.REDACT:
            return ExecutionStatus.REDACTION_REQUIRED

        if decision == Decision.RATE_LIMIT:
            return ExecutionStatus.RATE_LIMITED

        return ExecutionStatus.NOT_EXECUTED

def enforce_action(
    action: ActionScript,
    trap: LobsterTrapFinding,
    inference: AxiomLNNInference,
    thresholds: GateThresholds | None = None,
) -> EnforcementDecision:
    """
    Convenience function for callers that do not need to manage a gate instance.
    """

    return DeterministicGate(thresholds=thresholds).enforce(
        action=action,
        trap=trap,
        inference=inference,
    )