from pathlib import Path

from axiomguard_core.evidence import (
    build_receipt_chain,
    calculate_owasp_coverage,
    generate_executive_summary,
    generate_judge_report_markdown,
    map_tags_to_owasp,
    save_judge_report,
    save_owasp_coverage,
    simulate_receipt_tamper,
)
from axiomguard_core.pipeline import PipelineOptions, run_axiomguard_pipeline
from axiomguard_core.redteam import run_redteam_suite
from axiomguard_core.schemas import (
    ActionScript,
    ActionType,
    ActorProfile,
    DataClass,
    DestinationType,
    LobsterTrapFinding,
    ToolName,
)


def make_receipted_pipeline_result(tmp_path: Path):
    actor = ActorProfile(
        id="user_test",
        role="procurement_analyst",
        department="procurement",
        approval_limit_usd=0,
    )

    action = ActionScript(
        action_id="evidence_action_001",
        actor=actor,
        declared_intent="Summarize invoice.",
        detected_intent="Summarize invoice.",
        action_type=ActionType.SUMMARIZE_INVOICE,
        tool_name=ToolName.DOCS_SUMMARIZE,
        resource_id="invoice_101",
        destination=DestinationType.INTERNAL_UI,
        data_classes=[DataClass.CONTRACT_TERMS],
    )

    return run_axiomguard_pipeline(
        action=action,
        lobstertrap_findings=LobsterTrapFinding(risk_score=10),
        options=PipelineOptions(
            persist_receipt=True,
            export_markdown=False,
            receipt_directory=tmp_path,
        ),
    )


def test_map_tags_to_owasp():
    risks = map_tags_to_owasp(
        ["prompt_injection", "pii", "external_email", "high_value_transaction"]
    )

    assert "LLM01:2025 Prompt Injection" in risks
    assert "LLM02:2025 Sensitive Information Disclosure" in risks
    assert "LLM06:2025 Excessive Agency" in risks


def test_calculate_owasp_coverage_from_suite():
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=False,
    )

    coverage = calculate_owasp_coverage(suite)

    assert "coverage" in coverage
    assert "scenario_map" in coverage
    assert "LLM01:2025 Prompt Injection" in coverage["coverage"]
    assert "LLM02:2025 Sensitive Information Disclosure" in coverage["coverage"]
    assert "LLM06:2025 Excessive Agency" in coverage["coverage"]


def test_generate_executive_summary():
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=False,
    )

    summary = generate_executive_summary(suite)

    assert "headline" in summary
    assert "not represent a universal security guarantee" in summary["disclaimer"]
    assert summary["scenarios_tested"] >= 8
    assert summary["decision_receipts_generated"] == summary["scenarios_tested"]
    assert "owasp_coverage" in summary


def test_generate_judge_report_markdown_contains_key_sections():
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=False,
    )

    report = generate_judge_report_markdown(suite)

    assert "AxiomGuard CISO Compliance Evidence Pack" in report
    assert "OWASP LLM Risk Coverage" in report
    assert "Scenario Execution Evidence" in report
    assert "Gemini / MockPlanner" in report
    assert "Decision Receipt" in report
    assert "SHA-256" in report
    assert "HMAC" not in report


def test_save_judge_report_and_owasp_coverage(tmp_path: Path):
    suite = run_redteam_suite(
        scenario_path="data/redteam/attacks.json",
        persist_receipts=False,
    )

    report_path = save_judge_report(
        suite,
        path=tmp_path / "report.md",
    )

    coverage_path = save_owasp_coverage(
        suite,
        path=tmp_path / "owasp.json",
    )

    assert report_path.exists()
    assert coverage_path.exists()
    assert "AxiomGuard CISO" in report_path.read_text(encoding="utf-8")
    assert "LLM01" in coverage_path.read_text(encoding="utf-8")


def test_build_receipt_chain(tmp_path: Path):
    result = make_receipted_pipeline_result(tmp_path)

    chain = build_receipt_chain(tmp_path)

    assert len(chain) == 1
    assert chain[0]["receipt_id"] == result.receipt.receipt_id
    assert chain[0]["hash_valid"] is True
    assert chain[0]["decision"] == "ALLOW"
    assert chain[0]["tool_name"] == "docs.summarize"


def test_simulate_receipt_tamper_detects_modified_receipt(tmp_path: Path):
    result = make_receipted_pipeline_result(tmp_path)

    tamper_result = simulate_receipt_tamper(result.receipt)

    assert tamper_result["receipt_id"] == result.receipt.receipt_id
    assert tamper_result["original_hash"] == result.receipt.receipt_hash
    assert tamper_result["tampered_hash_valid"] is False
    assert tamper_result["security_result"] == "tamper_detected"