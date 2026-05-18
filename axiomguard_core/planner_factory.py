from __future__ import annotations

import os

from dotenv import load_dotenv

from axiomguard_core.planner import GeminiPlanner, MockPlanner, Planner

load_dotenv()


def get_planner() -> Planner:
    """
    Return the configured AxiomGuard planner.

    AXIOMGUARD_PLANNER=gemini uses Gemini 2.5 Flash.
    Any other value falls back to MockPlanner for deterministic demos.
    """

    mode = os.getenv("AXIOMGUARD_PLANNER", "mock").strip().lower()

    if mode == "gemini":
        return GeminiPlanner(
            api_key=os.getenv("GEMINI_API_KEY"),
            model_name=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        )

    return MockPlanner()