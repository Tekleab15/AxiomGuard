axiomguard/
│
├── README.md
├── LICENSE
├── .env.example
├── .gitignore
├── requirements.txt
├── pyproject.toml
├── Makefile
├── Dockerfile
├── docker-compose.yml
│
├── docs/
│   ├── architecture.md
│   ├── threat_model.md
│   ├── decision_receipts.md
│   ├── redteam_methodology.md
│   ├── demo_script.md
│   └── judge_pitch.md
│
├── submission/
│   ├── short_description.md
│   ├── long_description.md
│   ├── technology_tags.md
│   ├── video_script.md
│   ├── slide_outline.md
│   ├── cover_image_prompt.md
│   └── screenshots/
│
├── configs/
│   ├── axiomguard.yaml
│   ├── policies.yaml
│   └── lobstertrap_policy.yaml
│
├── data/
│   ├── demo/
│   │   ├── clean_invoice.json
│   │   ├── high_value_invoice.json
│   │   ├── clean_contract.txt
│   │   ├── injected_contract.txt
│   │   ├── employee_records_sample.csv
│   │   └── vendor_profile.json
│   │
│   ├── redteam/
│   │   ├── attacks.json
│   │   ├── expected_results.json
│   │   ├── baseline_results.json
│   │   └── axiomguard_results.json
│   │
│   └── receipts/
│       ├── samples/
│       │   ├── sample_allow.json
│       │   ├── sample_deny.json
│       │   ├── sample_human_review.json
│       │   └── sample_quarantine.json
│       └── generated/
│
├── axiomguard_core/
│   ├── __init__.py
│   ├── schemas.py
│   ├── prompts.py
│   ├── planner.py
│   ├── trap.py
│   ├── verifier.py
│   ├── enforcer.py
│   ├── receipts.py
│   ├── tools.py
│   ├── redteam.py
│   ├── pipeline.py
│   └── utils.py
│
├── apps/
│   ├── api/
│   │   ├── main.py
│   │   └── routes.py
│   │
│   └── web/
│       ├── streamlit_app.py
│       ├── pages/
│       │   ├── 1_Agent_Console.py
│       │   ├── 2_Decision_Receipts.py
│       │   ├── 3_Red_Team_Replay.py
│       │   ├── 4_AxiomLNN_Trace.py
│       │   └── 5_Metrics.py
│       │
│       └── components/
│           ├── risk_cards.py
│           ├── receipt_viewer.py
│           ├── trace_viewer.py
│           ├── attack_table.py
│           └── architecture_panel.py
│
├── scripts/
│   ├── run_redteam.py
│   ├── inspect_with_lobstertrap.py
│   ├── generate_sample_receipts.py
│   ├── export_audit_report.py
│   └── smoke_test_pipeline.py
│
├── tests/
│   ├── test_schemas.py
│   ├── test_verifier.py
│   ├── test_enforcer.py
│   ├── test_receipts.py
│   ├── test_tools.py
│   ├── test_redteam.py
│   └── test_pipeline.py
│
├── infra/
│   ├── render.yaml
│   ├── huggingface_space.Dockerfile
│   └── streamlit_config.toml
│
└── notebooks/
    └── axiom_lnn_experiments.ipynb