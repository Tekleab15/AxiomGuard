"""
AxiomLNN verifier for AxiomGuard.

This module converts:
- Gemini ActionScript facts
- Lobster Trap risk metadata

into:
- truth-bound logical policy decisions
- contradiction loss
- matched policy formula traces

The design is IBM-LNN compatible:
- facts are predicate-like truth values
- policies are logical formulas
- decision nodes have truth bounds
- contradictions are surfaced as a loss signal

For hackathon stability, this file implements a lightweight deterministic
LNN-style verifier first. A direct IBM/LNN adapter can be added later without
changing the rest of the AxiomGuard pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    AxiomLNNInference,
    DataClass,
    Decision,
    DestinationType,
    LobsterTrapFinding,
    MatchedFormula,
    RiskSignal,
    ToolName,
    TruthBound,
)

# -----------------------------------
# Internal constants
# -----------------------------------

SENSITIVE_DATA_CLASSES: set[DataClass] = {
    DataClass.VENDOR_BANK_DETAILS,
    DataClass.EMPLOYEE_PII,
    DataClass.CUSTOMER_PII,
    DataClass.SALARY_DATA,
    DataClass.SSN,
    DataClass.CREDENTIAL,
    DataClass.SECRET,
}

SECRET_DATA_CLASSES: set[DataClass] = {
    DataClass.CREDENTIAL,
    DataClass.SECRET,
    DataClass.SSN,
}

HIGH_RISK_INTENT_CATEGORIES: set[str] = {
    "data_exfiltration",
    "credential_access",
    "financial_execution",
    "unauthorized_action",
    "risky_command",
    "prompt_injection",
}

# -----------------------------------------
# Formula representation
# -----------------------------------------

@dataclass(frozen=True)
class FormulaEvaluation:
    policy_id: str
    name: str
    decision: Decision
    formula: str
    score: float
    trace: str


@dataclass(frozen=True)
class VerifierConfig:
    """
    Confidence values for policy conclusions.

    These are intentionally high for deterministic enterprise policy matches,
    while still expressed as truth scores so the output looks and behaves like
    a Logical Neural Network inference layer.
    """
    hard_match_score: float = 0.97
    strong_match_score: float = 0.92
    moderate_match_score: float = 0.85
    weak_match_score: float = 0.60
    unknown_upper_bound: float = 0.05


# ---------------------------------------------------------------------------
# Lightweight LNN-style logical operators
# ------------------------------------------

def lnn_not(value: float) -> float:
    return clamp01(1.0 - value)

def lnn_and(*values: float) -> float:
    if not values:
        return 0.0
    return clamp01(min(values))

def lnn_or(*values: float) -> float:
    if not values:
        return 0.0
    return clamp01(max(values))

def lnn_implies(antecedent: float, consequent: float) -> float:
    """
    Kleene/Lukasiewicz-style implication proxy:
    A -> B is true when A is false or B is true.

    In this MVP verifier we mainly use formula antecedent scores to derive
    decision-node truth values. This function is included for explicitness and
    future IBM-LNN alignment.
    """

    return clamp01(max(1.0 - antecedent, consequent))

def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))

def bool_score(value: bool) -> float:
    return 1.0 if value else 0.0

def risk_at_least_score(risk_score: float, threshold: float) -> float:
    """
    Convert a 0-100 risk score into a crisp threshold fact.

    AxiomGuard keeps the final execution gate deterministic, so risk thresholds
    are intentionally crisp for demo clarity.
    """

    return 1.0 if risk_score >= threshold else 0.0

def to_truth_bound(score: float, unknown_upper_bound: float = 0.05) -> TruthBound:
    """
    Convert a policy score to an open-world-style truth bound.

    - If the score is zero, the lower bound is 0 and upper bound is small.
    - If the score is nonzero, the lower bound is the score and the upper bound
      allows a small confidence interval up to 1.0.

    This mirrors the Decision Receipt examples:
        HumanReview = [0.97, 1.00]
        Allow = [0.00, 0.05]
    """

    score = clamp01(score)

    if score == 0.0:
        return TruthBound(lower=0.0, upper=unknown_upper_bound)

    return TruthBound(lower=score, upper=min(1.0, score + 0.03))

# ---------------------------------------
# Fact extraction
# ---------------------------------------

def extract_action_facts(
    action: ActionScript,
    trap: LobsterTrapFinding,
) -> dict[str, bool | float | str]:
    """
    Convert ActionScript + Lobster Trap metadata into logical facts.

    These facts are the bridge between:
    - Gemini's structured planning
    - Lobster Trap's prompt/response metadata
    - AxiomLNN's policy formulas
    """

    data_classes = set(action.data_classes)

    contains_sensitive_data = any(
        data_class in SENSITIVE_DATA_CLASSES
        for data_class in data_classes
    )

    contains_secret = any(
        data_class in SECRET_DATA_CLASSES
        for data_class in data_classes
    )

    detected_intent_category = (
        trap.detected_intent_category or "unknown"
    ).strip().lower()

    declared_intent_category = (
        trap.declared_intent_category or "unknown"
    ).strip().lower()

    detected_intent_high_risk = (
        detected_intent_category in HIGH_RISK_INTENT_CATEGORIES
        or trap.intent_mismatch
    )

    declared_intent_safe = declared_intent_category in {
        "safe",
        "read_only",
        "summary",
        "document_summary",
        "unknown",
    }

    facts: dict[str, bool | float | str] = {
        # Identity
        "ActionId": action.action_id,
        "ActorId": action.actor.id,
        "ActorRole": action.actor.role,
        "ActionType": action.action_type.value,
        "ToolName": action.tool_name.value,
        "Destination": action.destination.value,

        # Action predicates
        "SummarizeInvoice": action.action_type == ActionType.SUMMARIZE_INVOICE,
        "SummarizeContract": action.action_type == ActionType.SUMMARIZE_CONTRACT,
        "SummarizeDocument": action.action_type
        in {ActionType.SUMMARIZE_INVOICE, ActionType.SUMMARIZE_CONTRACT},
        "ApproveInvoice": action.action_type == ActionType.APPROVE_INVOICE,
        "SendEmail": action.action_type == ActionType.SEND_EMAIL,
        "CreateApprovalPacket": action.action_type
        == ActionType.CREATE_APPROVAL_PACKET,
        "CreateRedactedReport": action.action_type
        == ActionType.CREATE_REDACTED_REPORT,

        # Tool predicates
        "UsesDocsSummarizeTool": action.tool_name == ToolName.DOCS_SUMMARIZE,
        "UsesERPApprovalTool": action.tool_name == ToolName.ERP_APPROVE_INVOICE,
        "UsesEmailTool": action.tool_name == ToolName.EMAIL_SEND,
        "UsesApprovalPacketTool": action.tool_name
        == ToolName.WORKFLOW_CREATE_APPROVAL_PACKET,
        "UsesRedactedReportTool": action.tool_name
        == ToolName.REPORTS_CREATE_REDACTED_REPORT,

        # Destination predicates
        "InternalDestination": action.destination
        in {
            DestinationType.INTERNAL_UI,
            DestinationType.ERP_INTERNAL,
            DestinationType.MANAGER_QUEUE,
            DestinationType.INTERNAL_HR_DASHBOARD,
        },
        "ExternalDestination": action.destination == DestinationType.EXTERNAL_DOMAIN,
        "ManagerQueueDestination": action.destination == DestinationType.MANAGER_QUEUE,
        "InternalHRDashboard": action.destination
        == DestinationType.INTERNAL_HR_DASHBOARD,

        # Data predicates
        "ContainsSensitiveData": contains_sensitive_data,
        "ContainsSecrets": contains_secret,
        "ContainsPII": trap.pii_detected
        or any(
            item in data_classes
            for item in {
                DataClass.EMPLOYEE_PII,
                DataClass.CUSTOMER_PII,
                DataClass.SSN,
            }
        ),
        "ContainsCredential": trap.credential_detected
        or DataClass.CREDENTIAL in data_classes,

        # Finance predicates
        "AmountUSD": action.amount_usd or 0.0,
        "ActorApprovalLimitUSD": action.actor.approval_limit_usd,
        "AmountAboveActorLimit": action.is_high_value_transaction,

        # Lobster Trap predicates
        "PromptInjection": trap.prompt_injection
        or RiskSignal.PROMPT_INJECTION in action.risk_signals,
        "ExfiltrationDetected": trap.exfiltration_detected
        or RiskSignal.EXFILTRATION in action.risk_signals,
        "CredentialDetected": trap.credential_detected,
        "RiskyCommandDetected": trap.risky_command_detected,
        "IntentMismatch": trap.intent_mismatch,
        "LobsterTrapRiskScore": trap.risk_score,
        "LobsterTrapRiskAtLeast90": trap.risk_score >= 90.0,
        "LobsterTrapRiskAtLeast75": trap.risk_score >= 75.0,
        "LowRisk": trap.risk_score < 50.0,

        # Intent predicates
        "DeclaredIntentCategory": declared_intent_category,
        "DetectedIntentCategory": detected_intent_category,
        "DeclaredIntentSafe": declared_intent_safe,
        "DetectedIntentHighRisk": detected_intent_high_risk,
    }

    return facts

# -------------------------------------
# Verifier implementation
# -------------------------------------

class AxiomLNNVerifier:
    """
    A lightweight Logical Neural Network-style policy verifier.

    It evaluates a fixed enterprise policy pack over extracted facts and returns
    truth bounds and traces compatible with AxiomGuard's Decision Receipts.
    """
    def __init__(self, config: VerifierConfig | None = None) -> None:
        self.config = config or VerifierConfig()

    def verify(
        self,
        action: ActionScript,
        trap: LobsterTrapFinding,
    ) -> AxiomLNNInference:
        facts = extract_action_facts(action, trap)
        evaluations = self._evaluate_all_formulas(action, trap, facts)

        scores = self._aggregate_decision_scores(evaluations)
        contradiction_loss = self._calculate_contradiction_loss(scores)
        matched_formulas = self._to_matched_formulas(evaluations)

        trace = self._build_trace(
            action=action,
            trap=trap,
            facts=facts,
            evaluations=evaluations,
            scores=scores,
            contradiction_loss=contradiction_loss,
        )

        return AxiomLNNInference(
            allow=to_truth_bound(
                scores[Decision.ALLOW],
                self.config.unknown_upper_bound,
            ),
            deny=to_truth_bound(
                scores[Decision.DENY],
                self.config.unknown_upper_bound,
            ),
            redact=to_truth_bound(
                scores[Decision.REDACT],
                self.config.unknown_upper_bound,
            ),
            quarantine=to_truth_bound(
                scores[Decision.QUARANTINE],
                self.config.unknown_upper_bound,
            ),
            human_review=to_truth_bound(
                scores[Decision.HUMAN_REVIEW],
                self.config.unknown_upper_bound,
            ),
            rate_limit=to_truth_bound(
                scores[Decision.RATE_LIMIT],
                self.config.unknown_upper_bound,
            ),
            contradiction_loss=contradiction_loss,
            matched_formulas=matched_formulas,
            facts=facts,
            trace=trace,
        )

    # ------------------------------------------------------------------
    # Formula evaluation
    # ------------------------------------------------------------------

    def _evaluate_all_formulas(
        self,
        action: ActionScript,
        trap: LobsterTrapFinding,
        facts: dict[str, bool | float | str],
    ) -> list[FormulaEvaluation]:
        evaluations: list[FormulaEvaluation] = []

        evaluations.append(self._formula_sec_003(facts))
        evaluations.append(self._formula_sec_004(facts))
        evaluations.append(self._formula_data_002(facts))
        evaluations.append(self._formula_data_003(facts))
        evaluations.append(self._formula_sec_005(facts))
        evaluations.append(self._formula_fin_001(facts))
        evaluations.append(self._formula_intent_001(facts))
        evaluations.append(self._formula_risk_001(facts))
        evaluations.append(self._formula_proc_004(facts))
        evaluations.append(self._formula_workflow_001(facts))
        evaluations.append(self._formula_report_001(facts))
        evaluations.append(self._formula_comm_001(facts))

        return evaluations

    def _formula_sec_003(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = lnn_or(
            bool_score(bool(facts["PromptInjection"])),
            bool_score(bool(facts["ExfiltrationDetected"])),
        )

        score = self.config.hard_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="SEC-003",
            name="Quarantine prompt injection or exfiltration",
            decision=Decision.QUARANTINE,
            formula="PromptInjection(x) OR ExfiltrationDetected(x) -> Quarantine(x)",
            score=score,
            trace=(
                "Prompt injection or exfiltration implies quarantine."
                if score > 0
                else "No prompt injection or exfiltration was detected."
            ),
        )

    def _formula_sec_004(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = bool_score(bool(facts["LobsterTrapRiskAtLeast90"]))
        score = self.config.hard_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="SEC-004",
            name="Quarantine extremely high Lobster Trap risk",
            decision=Decision.QUARANTINE,
            formula="LobsterTrapRiskAtLeast90(x) -> Quarantine(x)",
            score=score,
            trace=(
                f"Lobster Trap risk score {facts['LobsterTrapRiskScore']} "
                "is at least 90, requiring quarantine."
                if score > 0
                else "Lobster Trap risk score is below quarantine threshold."
            ),
        )

    def _formula_data_002(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = lnn_and(
            bool_score(bool(facts["SendEmail"])),
            bool_score(bool(facts["ContainsSensitiveData"])),
            bool_score(bool(facts["ExternalDestination"])),
        )

        score = self.config.hard_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="DATA-002",
            name="Deny external transfer of sensitive data",
            decision=Decision.DENY,
            formula=(
                "SendEmail(x) AND ContainsSensitiveData(x) "
                "AND ExternalDestination(x) -> Deny(x)"
            ),
            score=score,
            trace=(
                "Sending sensitive data to an external destination is denied."
                if score > 0
                else "No external sensitive-data email transfer was inferred."
            ),
        )

    def _formula_data_003(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = bool_score(bool(facts["CredentialDetected"]))
        score = self.config.hard_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="DATA-003",
            name="Deny credential exposure",
            decision=Decision.DENY,
            formula="CredentialDetected(x) -> Deny(x)",
            score=score,
            trace=(
                "Credential-like content was detected and must be denied."
                if score > 0
                else "No credential-like content was detected."
            ),
        )

    def _formula_sec_005(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = bool_score(bool(facts["RiskyCommandDetected"]))
        score = self.config.hard_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="SEC-005",
            name="Deny risky command execution",
            decision=Decision.DENY,
            formula="RiskyCommandDetected(x) -> Deny(x)",
            score=score,
            trace=(
                "Risky operational command was detected and must be denied."
                if score > 0
                else "No risky operational command was detected."
            ),
        )

    def _formula_fin_001(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = lnn_and(
            bool_score(bool(facts["ApproveInvoice"])),
            bool_score(bool(facts["AmountAboveActorLimit"])),
        )

        score = self.config.hard_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="FIN-001",
            name="High-value invoice approval requires human review",
            decision=Decision.HUMAN_REVIEW,
            formula="ApproveInvoice(x) AND AmountAboveActorLimit(x) -> HumanReview(x)",
            score=score,
            trace=(
                "ApproveInvoice and AmountAboveActorLimit imply HumanReview. "
                f"Amount=${float(facts['AmountUSD']):,.2f}; "
                f"actor limit=${float(facts['ActorApprovalLimitUSD']):,.2f}."
                if score > 0
                else "Invoice approval is not above actor approval limit."
            ),
        )

    def _formula_intent_001(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = lnn_or(
            bool_score(bool(facts["IntentMismatch"])),
            lnn_and(
                bool_score(bool(facts["DeclaredIntentSafe"])),
                bool_score(bool(facts["DetectedIntentHighRisk"])),
            ),
        )

        score = self.config.strong_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="INTENT-001",
            name="Declared intent mismatch requires human review",
            decision=Decision.HUMAN_REVIEW,
            formula=(
                "DeclaredIntentSafe(x) AND DetectedIntentHighRisk(x) "
                "-> HumanReview(x)"
            ),
            score=score,
            trace=(
                "Declared intent and detected intent mismatch requires human review."
                if score > 0
                else "No declared-versus-detected intent mismatch was inferred."
            ),
        )

    def _formula_risk_001(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = bool_score(bool(facts["LobsterTrapRiskAtLeast75"]))
        score = self.config.strong_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="RISK-001",
            name="Elevated Lobster Trap risk requires human review",
            decision=Decision.HUMAN_REVIEW,
            formula="LobsterTrapRiskAtLeast75(x) -> HumanReview(x)",
            score=score,
            trace=(
                f"Lobster Trap risk score {facts['LobsterTrapRiskScore']} "
                "is elevated and requires human review."
                if score > 0
                else "Lobster Trap risk score is below human-review threshold."
            ),
        )

    def _formula_proc_004(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = lnn_and(
            bool_score(bool(facts["SummarizeDocument"])),
            bool_score(bool(facts["InternalDestination"])),
            lnn_not(bool_score(bool(facts["ContainsSecrets"]))),
        )

        score = self.config.strong_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="PROC-004",
            name="Safe internal procurement summary",
            decision=Decision.ALLOW,
            formula=(
                "SummarizeDocument(x) AND InternalDestination(x) "
                "AND NOT ContainsSecrets(x) -> Allow(x)"
            ),
            score=score,
            trace=(
                "Safe read-only internal document summary is allowed."
                if score > 0
                else "The action does not satisfy safe internal summary conditions."
            ),
        )

    def _formula_workflow_001(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = lnn_and(
            bool_score(bool(facts["CreateApprovalPacket"])),
            bool_score(bool(facts["ManagerQueueDestination"])),
        )

        score = self.config.strong_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="WORKFLOW-001",
            name="Safe approval packet creation",
            decision=Decision.ALLOW,
            formula="CreateApprovalPacket(x) AND ManagerQueueDestination(x) -> Allow(x)",
            score=score,
            trace=(
                "Creating an approval packet for manager review is allowed."
                if score > 0
                else "The action does not create an approval packet for manager review."
            ),
        )

    def _formula_report_001(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = lnn_and(
            bool_score(bool(facts["CreateRedactedReport"])),
            bool_score(bool(facts["InternalHRDashboard"])),
        )

        score = self.config.strong_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="REPORT-001",
            name="Safe redacted report creation",
            decision=Decision.ALLOW,
            formula="CreateRedactedReport(x) AND InternalHRDashboard(x) -> Allow(x)",
            score=score,
            trace=(
                "Creating a redacted internal HR report is allowed."
                if score > 0
                else "The action does not create a redacted internal HR report."
            ),
        )

    def _formula_comm_001(
        self,
        facts: dict[str, bool | float | str],
    ) -> FormulaEvaluation:
        antecedent = lnn_and(
            bool_score(bool(facts["SendEmail"])),
            lnn_not(bool_score(bool(facts["ContainsSensitiveData"]))),
            lnn_not(bool_score(bool(facts["CredentialDetected"]))),
            bool_score(bool(facts["LowRisk"])),
        )

        score = self.config.moderate_match_score if antecedent > 0 else 0.0

        return FormulaEvaluation(
            policy_id="COMM-001",
            name="Safe non-sensitive external email",
            decision=Decision.ALLOW,
            formula=(
                "SendEmail(x) AND NOT ContainsSensitiveData(x) "
                "AND NOT CredentialDetected(x) AND LowRisk(x) -> Allow(x)"
            ),
            score=score,
            trace=(
                "Low-risk non-sensitive email is allowed."
                if score > 0
                else "The email action is not low-risk and non-sensitive."
            ),
        )

    # ------------------------------------------------------------------
    # Aggregation and contradiction management
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate_decision_scores(
        evaluations: list[FormulaEvaluation],
    ) -> dict[Decision, float]:
        scores = {
            Decision.ALLOW: 0.0,
            Decision.DENY: 0.0,
            Decision.REDACT: 0.0,
            Decision.QUARANTINE: 0.0,
            Decision.HUMAN_REVIEW: 0.0,
            Decision.RATE_LIMIT: 0.0,
        }

        for evaluation in evaluations:
            scores[evaluation.decision] = max(
                scores[evaluation.decision],
                evaluation.score,
            )

        return scores

    @staticmethod
    def _calculate_contradiction_loss(
        scores: dict[Decision, float],
    ) -> float:
        """
        Surface contradictory governance signals.

        Examples:
        - Allow and Quarantine both high
        - Allow and Deny both high
        - Allow and HumanReview both high

        The deterministic gate later treats elevated contradiction loss as
        a human-review trigger.
        """

        allow_score = scores[Decision.ALLOW]
        block_score = max(
            scores[Decision.QUARANTINE],
            scores[Decision.DENY],
            scores[Decision.HUMAN_REVIEW],
            scores[Decision.REDACT],
        )

        contradiction = min(allow_score, block_score)

        if contradiction < 0.50:
            return 0.0

        return round(contradiction, 4)

    @staticmethod
    def _to_matched_formulas(
        evaluations: list[FormulaEvaluation],
    ) -> list[MatchedFormula]:
        matched = []

        for evaluation in evaluations:
            if evaluation.score <= 0.0:
                continue

            matched.append(
                MatchedFormula(
                    policy_id=evaluation.policy_id,
                    decision=evaluation.decision,
                    formula=evaluation.formula,
                    score=evaluation.score,
                    trace=evaluation.trace,
                )
            )

        return matched

    @staticmethod
    def _build_trace(
        *,
        action: ActionScript,
        trap: LobsterTrapFinding,
        facts: dict[str, bool | float | str],
        evaluations: list[FormulaEvaluation],
        scores: dict[Decision, float],
        contradiction_loss: float,
    ) -> str:
        active_facts = [
            key
            for key, value in facts.items()
            if isinstance(value, bool) and value is True
        ]

        matched = [
            evaluation
            for evaluation in evaluations
            if evaluation.score > 0.0
        ]

        matched_lines = [
            (
                f"- {item.policy_id}: {item.formula} "
                f"=> {item.decision.value} ({item.score:.2f})"
            )
            for item in matched
        ]

        if not matched_lines:
            matched_lines = ["- No policy formula matched above zero confidence."]

        trace = f"""AxiomLNN Verification Trace

Action:
- action_id: {action.action_id}
- action_type: {action.action_type.value}
- tool_name: {action.tool_name.value}
- actor_role: {action.actor.role}
- destination: {action.destination.value}
- amount_usd: {action.amount_usd}

Lobster Trap:
- risk_score: {trap.risk_score}
- prompt_injection: {trap.prompt_injection}
- exfiltration_detected: {trap.exfiltration_detected}
- pii_detected: {trap.pii_detected}
- credential_detected: {trap.credential_detected}
- intent_mismatch: {trap.intent_mismatch}

Active Facts:
{chr(10).join(f"- {fact}" for fact in active_facts)}

Matched Policy Formulas:
{chr(10).join(matched_lines)}

Decision Node Scores:
- Allow: {scores[Decision.ALLOW]:.2f}
- Deny: {scores[Decision.DENY]:.2f}
- Redact: {scores[Decision.REDACT]:.2f}
- Quarantine: {scores[Decision.QUARANTINE]:.2f}
- HumanReview: {scores[Decision.HUMAN_REVIEW]:.2f}
- RateLimit: {scores[Decision.RATE_LIMIT]:.2f}

Contradiction Loss:
- {contradiction_loss:.2f}
"""
        return trace

# --------------------------------------
# Convenience API
# --------------------------------------

def verify_action(
    action: ActionScript,
    trap: LobsterTrapFinding,
    config: VerifierConfig | None = None,
) -> AxiomLNNInference:
    """
    Convenience function for pipeline callers.
    """

    return AxiomLNNVerifier(config=config).verify(action=action, trap=trap)

# ------------------------------------------------
# Optional IBM LNN probe / adapter placeholder
# ------------------------------------------------

class IBMLNNAdapterStatus:
    """
    Lightweight availability probe for the real IBM LNN package.

    This keeps AxiomGuard honest:
    - If IBM LNN is installed, future code can use it.
    - If not installed, the hackathon demo still works through the built-in
      lightweight AxiomLNN verifier.
    """
    @staticmethod
    def is_available() -> bool:
        try:
            import lnn  # noqa: F401
        except Exception:
            return False

        return True

    @staticmethod
    def import_error_message() -> str:
        return (
            "IBM LNN is not installed. The hackathon MVP uses the built-in "
            "lightweight AxiomLNN verifier. To experiment with IBM LNN, run: "
            "pip install git+https://github.com/IBM/LNN"
        )