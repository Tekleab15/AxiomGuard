from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[3]
WEB_DIR = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from components.receipt_viewer import render_receipt_file_selector


st.set_page_config(
    page_title="AxiomGuard Decision Receipts",
    page_icon="🧾",
    layout="wide",
)

st.title("🧾 Decision Receipts")
st.caption("Tamper-evident audit records for verified agent actions.")

st.markdown(
    """
    Every AxiomGuard decision produces a hashed Decision Receipt.

    This page lets you inspect receipts and simulate audit-log tampering.
    """
)

render_receipt_file_selector("data/receipts/generated")