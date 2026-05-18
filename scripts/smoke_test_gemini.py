from __future__ import annotations

from dotenv import load_dotenv

from axiomguard_core.pipeline import PipelineOptions, run_axiomguard_pipeline
from axiomguard_core.planner import PlannerRequest
from axiomguard_core.planner_factory import get_planner
from axiomguard_core.schemas import ActorProfile, LobsterTrapFinding

load_dotenv()

def main() -> None:
    actor = ActorProfile(
        id="user_gemini_test",
        role="finance_analyst",
        department="finance",
        approval_limit_usd=10000,
    )

    planner = get_planner()

    planned = planner.plan(
        PlannerRequest(
            actor=actor,
            user_prompt="Approve invoice_8821 for $52,000.",
            document_text=(
                "Invoice invoice_8821. Amount: 52000 USD. "
                "Vendor: Northstar Logistics. Contract appears matched."
            ),
        )
    )

    print("\nPlanner backend:", planned.planner_backend)
    print("\nGenerated ActionScript:")
    print(planned.action.model_dump_json(indent=2))

    result = run_axiomguard_pipeline(
        action=planned.action,
        lobstertrap_findings=LobsterTrapFinding(
            risk_score=12,
            declared_intent_category="financial_execution",
            detected_intent_category="financial_execution",
        ),
        options=PipelineOptions(
            execute_tools=True,
            persist_receipt=True,
            export_markdown=True,
            receipt_directory="data/receipts/generated",
            agent="gemini_2_5_flash_planner",
        ),
    )

    print("\nAxiomGuard Result:")
    print("Decision:", result.final_decision.value)
    print("Matched policy:", result.enforcement.matched_policy)
    print("Executed:", result.executed)
    print("Receipt:", result.receipt.receipt_id)
    print("Receipt hash:", result.receipt.receipt_hash)

if __name__ == "__main__":
    main()