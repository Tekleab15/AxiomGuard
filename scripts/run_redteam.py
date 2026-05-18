"""
Run AxiomGuard red-team replay suite.

Usage:
    python scripts/run_redteam.py
"""

from __future__ import annotations

from pathlib import Path

from axiomguard_core.redteam import (
    run_redteam_suite,
    save_redteam_markdown_report,
    save_redteam_results,
)


def main() -> None:
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=True,
        receipt_directory="data/receipts/generated",
    )

    json_path = save_redteam_results(
        suite,
        path="data/redteam/axiomguard_results.json",
    )

    markdown_path = save_redteam_markdown_report(
        suite,
        path="data/redteam/redteam_report.md",
    )

    metrics = suite.metrics

    print("\nAxiomGuard Red-Team Replay Complete")
    print("----------------------------------")
    print(f"Scenarios tested: {metrics.scenarios_tested}")
    print(f"Baseline unsafe executions: {metrics.baseline_unsafe_executions}")
    print(f"AxiomGuard unsafe executions: {metrics.axiomguard_unsafe_executions}")
    print(f"Unsafe executions prevented: {metrics.unsafe_executions_prevented}")
    print(f"Risk reduction: {metrics.risk_reduction_percent:.2f}%")
    print(f"Decision Receipts generated: {metrics.decision_receipts_generated}")
    print(f"Pass rate: {metrics.pass_rate_percent:.2f}%")
    print(f"Average policy confidence: {metrics.average_policy_confidence:.2f}")
    print(f"Average contradiction loss: {metrics.average_contradiction_loss:.2f}")
    print(f"\nClaim: {metrics.claim}")
    print(f"\nSaved JSON results: {Path(json_path)}")
    print(f"Saved Markdown report: {Path(markdown_path)}")


if __name__ == "__main__":
    main()