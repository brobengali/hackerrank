# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Solution Architecture

This system implements an end-to-end, multi-stage deletion audit agent that operates fully offline with zero API cost and strict deterministic guarantees:

1. **Typed Data Loading & Schema Validation** ([`code/core/loader.py`](./code/core/loader.py), [`code/core/schema_validator.py`](./code/core/schema_validator.py)): Validates schemas, preserves provenance, and prevents silent record drops.
2. **Dynamic Policy Engine** ([`code/core/policy_engine.py`](./code/core/policy_engine.py)): Parses `dataset/deletion_rules.csv` at runtime with full semantics for `DELETE`, `REDACT`, `ANONYMIZE`, `RETAIN`, and permitted `ACCOUNT_TOMBSTONE` references.
3. **Collision-Aware Identity Resolution** ([`code/core/identity.py`](./code/core/identity.py)): Reconstructs current and multi-hop historical identifiers (`user_audit_log.csv`) with collision protection.
4. **Point-in-Time Evidence Store** ([`code/core/evidence_store.py`](./code/core/evidence_store.py)): Indexes SQLite-compatible SQL snapshots, JSON records, system logs, text handovers, and PDF exports with strict temporal cutoff enforcement at `audit_at`.
5. **Cross-System Investigation** ([`code/core/investigator.py`](./code/core/investigator.py)): Uncovers prohibited residual personal data and exposed PII across all enterprise replicas and storage systems.
6. **Resurrection Risk Engine** ([`code/core/resurrection.py`](./code/core/resurrection.py)): Identifies active data flows (`integration_service`) and scheduled backup restore paths capable of recreating deleted data.
7. **Dependency-Aware Remediation Planner** ([`code/core/remediation_planner.py`](./code/core/remediation_planner.py)): Applies Kahn's topological sort with cycle detection, guaranteeing resurrection controls (`DISABLE_DATA_FLOW`, `BLOCK_RESTORE`) precede dependent record cleanups.
8. **Deterministic Verification Engine & Safety Gate** ([`code/core/verification_engine.py`](./code/core/verification_engine.py)): Computes final status (`COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`) and enforces 8 Python invariants that prevent false `COMPLETE` decisions.
9. **Bounded AI Investigator** ([`code/core/ai_investigator.py`](./code/core/ai_investigator.py)): Optional tool-calling loop defended against prompt injection with inert XML wrapping and fallback to deterministic execution.

---

## Installation & Environment Setup

The solution requires **Python 3.10+** (tested on Python 3.12). The deterministic audit engine and evaluation framework rely solely on standard library modules (`csv`, `json`, `sqlite3`, `pathlib`, `re`, `hashlib`, `unittest`, `argparse`).

To set up your environment:

```bash
# Clone the repository
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26

# Ensure PYTHONPATH includes the repository root
export PYTHONPATH=.       # macOS / Linux
$env:PYTHONPATH="."       # Windows PowerShell
set PYTHONPATH=.          # Windows CMD
```

---

## Execution Commands

### 1. Full Challenge Dataset Audit (518 Cases)

Runs the complete 13-stage pipeline across all 518 evaluation requests, producing root `output.csv`:

```bash
python3 code/main.py
```

On Windows:
```powershell
python code\main.py
```

Options:
- `--dataset <path>`: Directory containing dataset files (default: `dataset`).
- `--output <path>`: Destination path for prediction output (default: `output.csv`).
- `--eval-samples`: Run on `dataset/sample_deletion_requests.csv` and compute benchmark metrics against `dataset/sample_output.csv`.
- `--use-ai`: Enable optional AI-assisted investigation tool loop (requires `GEMINI_API_KEY`).

### 2. Sample Evaluation Benchmark Mode

Evaluates the agent on the 32 public labeled cases and prints comprehensive accuracy metrics:

```bash
python3 code/main.py --eval-samples
```

Or run the dedicated evaluation CLI:

```bash
python3 -m code.evaluation.main
```

---

## Running the Automated Test Suite

The repository contains **86 comprehensive automated tests** across 9 test modules covering all subsystems and generalization guarantees:

### Run All Tests:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

### Run Specific Test Modules:

| Test Module | Coverage |
|---|---|
| `tests/test_data_layer.py` | Schema validation, type checking, malformed input handling |
| `tests/test_policy_engine.py` | Dynamic rule parsing, tombstones, PII inspection |
| `tests/test_identity.py` | Historical identity resolution, collision detection |
| `tests/test_investigation.py` | Cross-system evidence querying, temporal cutoff enforcement |
| `tests/test_resurrection.py` | Data flow and restore risk detection |
| `tests/test_remediation_planner.py` | Kahn topological sort, cycle detection, flow-first ordering |
| `tests/test_verification_engine.py` | 8 safety gate invariants, override enforcement |
| `tests/test_ai_investigator.py` | Prompt injection defense, schema validation, loop bounds |
| `tests/test_generalization.py` | 9 generalization dimensions (UUIDs, multi-hop history, dynamic policies, fault isolation) |

To run the generalization tests individually:

```bash
python3 -m unittest tests/test_generalization.py
```


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.
