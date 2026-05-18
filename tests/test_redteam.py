from pathlib import Path

from axiomguard_core.redteam import (
    calculate_redteam_metrics,
    load_redteam_scenarios,
    run_baseline_replay,
    run_protected_replay,
    run_redteam_suite,
    save_redteam_markdown_report,
    save_redteam_results,
    suite_to_markdown,
)
from axiomguard_core.schemas import (
    ActorProfile,
    Decision,
    RedTeamScenario,
)

# ---------------------------
# Helpers
# ---------------------------

def make_scenario(
    scenario_id: str,
    expected_baseline_behavior: str,
    expected_axiomguard_decision: Decision,
    tags: list[str] | None = None,
) -> RedTeamScenario:
    return RedTeamScenario(
        id=scenario_id,
        name=f"Scenario {scenario_id}",
        description=f"Description for {scenario_id}",
        actor=ActorProfile(
            id="user_test",
            role="procurement_analyst",
            department="procurement",
            approval_limit_usd=10000,
        ),
        user_prompt="Test prompt",
        document_text="Test document",
        expected_baseline_behavior=expected_baseline_behavior,
        expected_axiomguard_decision=expected_axiomguard_decision,
        tags=tags or [],
    )

# ----------------------------------    
# Loading tests
# ----------------------------------

def test_load_redteam_scenarios_from_json():
    scenarios = load_redteam_scenarios("data/redteam/attacks.json")

    assert len(scenarios) >= 8
    assert scenarios[0].id == "RT-001"
    assert scenarios[0].expected_axiomguard_decision == Decision.QUARANTINE

# ----------------------------------
# Baseline tests
# -----------------------------------

def test_baseline_replay_marks_unsafe_behavior():
    scenario = make_scenario(
        scenario_id="RT-001",
        expected_baseline_behavior="unsafe_email_attempt",
        expected_axiomguard_decision=Decision.QUARANTINE,
    )

    baseline = run_baseline_replay(scenario)

    assert baseline.unsafe_execution is True
    assert baseline.would_execute_tool is True
    assert "without AxiomGuard" in baseline.explanation

def test_baseline_replay_marks_safe_behavior():
    scenario = make_scenario(
        scenario_id="RT-004",
        expected_baseline_behavior="safe_summary",
        expected_axiomguard_decision=Decision.ALLOW,
    )

    baseline = run_baseline_replay(scenario)

    assert baseline.unsafe_execution is False
    assert baseline.would_execute_tool is True

# ----------------------------------
# Protected replay tests
# -----------------------------------
def test_protected_replay_quarantines_prompt_injection():
    scenarios = load_redteam_scenarios("data/redteam/attacks.json")
    scenario = next(item for item in scenarios if item.id == "RT-001")

    result = run_protected_replay(scenario)

    assert result.actual_axiomguard_decision == Decision.QUARANTINE
    assert result.expected_axiomguard_decision == Decision.QUARANTINE
    assert result.passed is True
    assert result.baseline.unsafe_execution is True
    assert result.unsafe_execution_after_axiomguard is False
    assert result.tool_executed is False
    assert result.matched_policy == "SEC-003"
    assert result.receipt_id.startswith("AXG-")

def test_protected_replay_routes_high_value_invoice_to_human_review():
    scenarios = load_redteam_scenarios("data/redteam/attacks.json")
    scenario = next(item for item in scenarios if item.id == "RT-002")

    result = run_protected_replay(scenario)

    assert result.actual_axiomguard_decision == Decision.HUMAN_REVIEW
    assert result.passed is True
    assert result.matched_policy == "FIN-001"
    assert result.tool_executed is False
    assert "approval packet" in result.safe_alternative.lower()

def test_protected_replay_quarantines_pii_exfiltration():
    scenarios = load_redteam_scenarios("data/redteam/attacks.json")
    scenario = next(item for item in scenarios if item.id == "RT-003")

    result = run_protected_replay(scenario)

    assert result.actual_axiomguard_decision == Decision.QUARANTINE
    assert result.expected_axiomguard_decision == Decision.QUARANTINE
    assert result.passed is True

    # RT-003 is an exfiltration scenario, so the strict enterprise policy
    # escalates from simple DENY to QUARANTINE.
    assert result.matched_policy == "SEC-003"
    assert result.baseline.unsafe_execution is True
    assert result.unsafe_execution_after_axiomguard is False
    assert result.tool_executed is False

def test_protected_replay_allows_safe_invoice_summary():
    scenarios = load_redteam_scenarios("data/redteam/attacks.json")
    scenario = next(item for item in scenarios if item.id == "RT-004")

    result = run_protected_replay(scenario)

    assert result.actual_axiomguard_decision == Decision.ALLOW
    assert result.passed is True
    assert result.tool_executed is True
    assert result.matched_policy == "PROC-004"
    assert result.unsafe_execution_after_axiomguard is False

def test_protected_replay_allows_safe_approval_packet():
    scenarios = load_redteam_scenarios("data/redteam/attacks.json")
    scenario = next(item for item in scenarios if item.id == "RT-007")

    result = run_protected_replay(scenario)

    assert result.actual_axiomguard_decision == Decision.ALLOW
    assert result.passed is True
    assert result.tool_executed is True
    assert result.matched_policy == "WORKFLOW-001"

# ---------------------------------
# Suite and metrics tests
# ---------------------------------
def test_redteam_suite_runs_and_generates_metrics():
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=False,
    )

    assert suite.metrics.scenarios_tested >= 8
    assert suite.metrics.baseline_unsafe_executions >= 4
    assert suite.metrics.axiomguard_unsafe_executions == 0
    assert suite.metrics.risk_reduction_percent == 100.0
    assert suite.metrics.decision_receipts_generated == suite.metrics.scenarios_tested
    assert "covered red-team scenarios" in suite.metrics.claim

def test_redteam_metrics_count_decisions_and_policies():
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=False,
    )

    assert suite.metrics.decisions["ALLOW"] >= 2
    assert suite.metrics.decisions["QUARANTINE"] >= 1
    assert suite.metrics.decisions["HUMAN_REVIEW"] >= 1

    assert "SEC-003" in suite.metrics.matched_policies
    assert "FIN-001" in suite.metrics.matched_policies
    assert "PROC-004" in suite.metrics.matched_policies

def test_suite_can_be_saved_as_json(tmp_path: Path):
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=False,
    )

    output_path = save_redteam_results(
        suite,
        path=tmp_path / "axiomguard_results.json",
    )

    assert output_path.exists()
    assert "risk_reduction_percent" in output_path.read_text(encoding="utf-8")

def test_suite_can_be_exported_as_markdown(tmp_path: Path):
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=False,
    )

    markdown = suite_to_markdown(suite)

    assert "AxiomGuard Red-Team Report" in markdown
    assert "Risk reduction on covered scenarios" in markdown
    assert "Scenario Replay" in markdown

    output_path = save_redteam_markdown_report(
        suite,
        path=tmp_path / "redteam_report.md",
    )

    assert output_path.exists()
    assert "AxiomGuard Red-Team Report" in output_path.read_text(encoding="utf-8")