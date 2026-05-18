from __future__ import annotations

from pathlib import Path
from typing import Any

import streamlit as st

from axiomguard_core.evidence import simulate_receipt_tamper
from axiomguard_core.receipts import (
    export_receipt_markdown,
    load_receipt_json,
    verify_receipt_hash,
)
from axiomguard_core.schemas import DecisionReceipt


def render_receipt(receipt: DecisionReceipt) -> None:
    valid_hash = verify_receipt_hash(receipt)

    col1, col2, col3 = st.columns(3)
    col1.metric("Receipt ID", receipt.receipt_id)
    col2.metric("Decision", receipt.final_decision.value)
    col3.metric("Hash Valid", str(valid_hash))

    if valid_hash:
        st.success("Receipt integrity verified. The audit record has not been modified.")
    else:
        st.error("Receipt integrity check failed. This audit record may have been modified.")

    st.markdown(export_receipt_markdown(receipt))

    with st.expander("Raw Receipt JSON"):
        st.json(receipt.model_dump(mode="json"))

    render_tamper_alarm(receipt)


def render_receipt_file_selector(
    directory: str | Path = "data/receipts/generated",
) -> None:
    directory = Path(directory)

    if not directory.exists():
        st.info("No generated receipts found yet. Run the Red-Team Replay or Agent Console first.")
        return

    files = sorted(directory.glob("*.json"), reverse=True)

    if not files:
        st.info("No generated receipt JSON files found yet.")
        return

    selected = st.selectbox(
        "Select receipt",
        files,
        format_func=lambda path: path.name,
    )

    receipt = load_receipt_json(selected)
    render_receipt(receipt)


def render_receipt_from_dashboard_summary(summary: dict[str, Any]) -> None:
    st.markdown("### Decision Receipt Summary")

    col1, col2, col3 = st.columns(3)

    col1.metric("Receipt ID", summary["receipt_id"])
    col2.metric("Decision", summary["final_decision"])
    col3.metric("Receipt Hash", "present" if summary.get("receipt_hash") else "missing")

    st.json(
        {
            "receipt_id": summary["receipt_id"],
            "receipt_hash": summary["receipt_hash"],
            "final_decision": summary["final_decision"],
            "matched_policy": summary["matched_policy"],
            "reason": summary["reason"],
            "safe_alternative": summary["safe_alternative"],
            "action": summary["action"],
            "lobstertrap": summary["lobstertrap"],
            "lnn": summary["lnn"],
            "tool_result": summary["tool_result"],
        }
    )


def render_tamper_alarm(receipt: DecisionReceipt) -> None:
    """
    Interactive malicious-insider tamper simulation.

    Demonstrates that Decision Receipts are tamper-evident.
    """

    st.markdown("---")
    st.markdown("## 🚨 Cryptographic Tamper Alarm")
    st.caption(
        "Simulate a malicious insider modifying an audit receipt after the fact."
    )

    valid_before = verify_receipt_hash(receipt)

    col1, col2, col3 = st.columns(3)
    col1.metric("Original Hash Valid", str(valid_before))
    col2.metric("Original Decision", receipt.final_decision.value)
    col3.metric("Matched Policy", receipt.enforcement.matched_policy)

    st.code(
        """
Attack simulation:
1. A valid Decision Receipt is generated.
2. A malicious insider modifies the enforcement reason.
3. AxiomGuard recomputes integrity verification.
4. The modified receipt fails hash verification.
        """.strip(),
        language="text",
    )

    if st.button("🚨 Simulate Audit Log Tampering", type="secondary"):
        tamper_result = simulate_receipt_tamper(receipt)

        if tamper_result["security_result"] == "tamper_detected":
            st.error(
                "🚨 CRITICAL: Cryptographic signature mismatch detected. "
                "Decision Receipt was modified after verification."
            )
        else:
            st.warning("Unexpected: tampered receipt still appears valid.")

        st.json(tamper_result)