# 🛡️ AxiomGuard

**AxiomGuard** is a tamper-evident governance control plane for enterprise AI agents.

It protects agentic workflows by separating planning from authorization:

```text
Gemini / MockPlanner → ActionScript
Lobster Trap → risk metadata
AxiomLNN → truth-bound policy inference
Deterministic Gate → final enforcement decision
Decision Receipt → tamper-evident audit artifact
Receipt-Required Executor → tool execution only if ALLOW
```

AxiomGuard is built for the Agent Security & AI Governance track of the AI and Big Data Expo Hackathon.

🚀 One-Line Pitch
AxiomGuard prevents unauthorized AI-agent execution by requiring every tool call to pass symbolic verification and produce a tamper-evident Decision Receipt.

🧠 Why AxiomGuard Exists
Enterprise AI agents can read files, call APIs, send messages, and trigger business workflows. But most current guardrails are prompt-based and probabilistic.

AxiomGuard introduces a stricter pattern: The model may propose an action, but it cannot authorize execution.

✨ Core Features
1. Deterministic Execution Gate
AxiomGuard enforces a strict priority order:

QUARANTINE > DENY > HUMAN_REVIEW > REDACT > RATE_LIMIT > ALLOW

Only ALLOW can execute a tool.

2. AxiomLNN Symbolic Verification
AxiomGuard converts structured agent intent and inspection metadata into logical facts and truth-bound decision nodes:

- Allow(x)
- Deny(x)
- HumanReview(x)
- Quarantine(x)

ApproveInvoice(x) AND AmountAboveActorLimit(x) → HumanReview(x)

This gives the system explainable, formula-level governance instead of relying only on prompt instructions.

3. Decision Receipts
Every attempted action generates a Decision Receipt containing:
 - Actor identity
 - Proposed action
 - Lobster Trap findings
 - AxiomLNN truth bounds
 - Matched policy
 - Final gate decision
 - Safe alternative
 - SHA-256 receipt hash
 - Optional previous receipt hash

Tamper-Evident: Decision Receipts are immutable. If a receipt is modified after generation, the cryptographic hash verification fails.

4. Receipt-Required Tool Execution
AxiomGuard simulated enterprise tools refuse to run unless a valid ALLOW receipt is presented. Protected simulated tools include:

docs.summarize

erp.approve_invoice

email.send

workflow.create_approval_packet

reports.create_redacted_report

5. Red-Team Replay Suite
AxiomGuard includes repeatable red-team scenarios for:

Prompt injection

Exfiltration

Employee PII export

Credential leakage

High-value invoice approval

Declared-vs-detected intent mismatch

Safe approval packet creation

Safe redacted reporting

The suite compares baseline unsafe behavior with AxiomGuard-protected behavior.

6. OWASP LLM Risk Mapping
Red-team scenarios are mapped to OWASP LLM risk categories, including:

LLM01:2025 Prompt Injection

LLM02:2025 Sensitive Information Disclosure

LLM05:2025 Improper Output Handling

LLM06:2025 Excessive Agency

7. Executive Evidence Dashboard
The Streamlit dashboard provides:
 - Risk-reduction metrics
 - OWASP coverage & Matched policy coverage
 - Receipt-chain timeline & Decision Receipt inspection
 - Malicious insider tamper alarm
 - AxiomLNN contradiction sandbox
 - CISO compliance export pack

🧩 Architecture
                        ┌──────────────────────┐
                        │ User Request         │
                        │ Enterprise Document  │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ Gemini / MockPlanner │
                        │ Produces ActionScript│
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ Lobster Trap Finding │
                        │ Risk + DPI metadata  │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ AxiomLNN Verifier    │
                        │ Truth-bound policies │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ Deterministic Gate   │
                        │ Final decision       │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ Decision Receipt     │
                        │ Tamper-evident audit │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │ Receipt Executor     │
                        │ Tool runs only if    │
                        │ receipt is valid     │
                        │ and decision is ALLOW│
                        └──────────────────────┘

📁 Repository Structure
AxiomGuard/
├── axiomguard_core/
│   ├── schemas.py          # Pydantic contracts
│   ├── enforcer.py         # deterministic execution gate
│   ├── verifier.py         # AxiomLNN-style policy inference
│   ├── receipts.py         # Decision Receipt hashing and export
│   ├── tools.py            # receipt-required simulated tools
│   ├── pipeline.py         # end-to-end control plane
│   ├── planner.py          # MockPlanner and GeminiPlanner
│   ├── prompts.py          # schema-synced planner prompts
│   ├── redteam.py          # red-team replay engine
│   └── evidence.py         # OWASP mapping and compliance evidence
│
├── apps/
│   └── web/
│       ├── streamlit_app.py
│       ├── styles.py
│       ├── components/
│       └── pages/
│           ├── 1_Agent_Console.py
│           ├── 2_Decision_Receipts.py
│           ├── 3_Red_Team_Replay.py
│           ├── 4_AxiomLNN_Trace.py
│           ├── 5_Metrics.py
│           └── 6_Executive_Evidence.py
│
├── data/
│   ├── redteam/
│   │   ├── attacks.json
│   │   ├── axiomguard_results.json
│   │   ├── owasp_coverage.json
│   │   └── AxiomGuard_CISO_Compliance_Report.md
│   └── receipts/
│       └── generated/
│
├── scripts/
│   └── run_redteam.py
│
├── tests/
├── requirements.txt
├── Dockerfile
└── README.md

⚙️ Installation
Clone the repository:
```bash
git clone [https://github.com/](https://github.com/)<your-username>/AxiomGuard.git
cd AxiomGuard
```
Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
Install dependencies:
```bash
pip install -r requirements.txt
```
🧪 Run Tests
Run the full test suite:
```bash 
python -m pytest tests
```
Run selected components:
```bash 
python -m pytest tests/test_enforcer.py
python -m pytest tests/test_verifier.py
python -m pytest tests/test_pipeline.py
python -m pytest tests/test_redteam.py
python -m pytest tests/test_evidence.py
```
▶️ Run the Streamlit App
```bash
streamlit run apps/web/streamlit_app.py
```

Recommended Demo Order:
    1. Executive Evidence
    2. Red-Team Replay
    3. Agent Console
    4. Decision Receipts
    5. AxiomLNN Trace
    6. Metrics

🔥 Run Red-Team Replay
```bash
python scripts/run_redteam.py
```
This generates:
 - data/redteam/axiomguard_results.json
 - data/redteam/redteam_report.md
 - data/redteam/AxiomGuard_CISO_Compliance_Report.md
 - data/redteam/owasp_coverage.json
 - data/receipts/generated/*.json

🧾 Decision Receipt Example
```json 
  {
  "receipt_id": "AXG-20260518-A1B2C3D4",
  "final_decision": "HUMAN_REVIEW",
  "matched_policy": "FIN-001",
  "reason": "Invoice amount exceeds actor approval limit.",
  "receipt_hash": "sha256:..."
    }
A receipt is valid only if the stored hash matches the canonical JSON payload.

🧠 AxiomLNN Example
A high-value invoice approval creates the facts:
 - ApproveInvoice(action_8821)
 - AmountAboveActorLimit(action_8821)

AxiomLNN applies the rule:
ApproveInvoice(x) AND AmountAboveActorLimit(x) → HumanReview(x)

Inference:
   - HumanReview(action_8821) = [0.97, 1.00]
The deterministic gate blocks tool execution and routes the request to human review.

🛡️ Security Model
AxiomGuard assumes:
 - The LLM may hallucinate.
 - The user prompt may be adversarial.
 - Enterprise documents may contain hidden instructions.
 - Tool calls may cause business impact.
 - Audit logs must be tamper-evident.

AxiomGuard therefore enforces: No valid ALLOW receipt → no tool execution.

📊 Current Evidence Metrics
Generated by the red-team replay suite:
 - Baseline unsafe executions: measured from scenario fixtures
 - AxiomGuard unsafe executions: measured after pipeline enforcement
 - Risk reduction: calculated only on covered red-team scenarios
 - Decision Receipts: generated for each protected replay

Important: AxiomGuard does not claim universal security. It reports measured reduction on the provided red-team scenario suite.