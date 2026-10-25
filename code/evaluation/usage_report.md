# Usage Report: Ghost Data Still Exists Deletion Audit Agent

**Challenge**: HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Submission**: `output.csv` (Full Evaluation Dataset: 518 cases)  
**Execution Timestamp**: 2026-10-24T21:27:50Z  
**Primary Execution Engine**: Deterministic Verification & Cross-System Evidence Engine  
**Optional AI Subsystem**: `AIAssistedInvestigator` (`Gemini 3.8 Flash (Medium)` / `MockLLMProvider`)  

---

## 1. Full Dataset Run Summary (518 Requests)

The final `output.csv` submitted for the October 2026 challenge was generated using the deterministic Python verification pipeline. This engine enforces the complete policy contract, cross-system evidence store, Kahn topological remediation ordering, and post-model safety gate without requiring external model API calls.

| Metric | Full Dataset Run Value |
|---|---|
| **Total Deletion Requests Audited** | **518** |
| **Model Providers Used** | Deterministic Python Verification Engine (Native) |
| **Model Names** | `deterministic-rules-engine-v1.0` |
| **Total Model Calls** | **0** |
| **Total Input Tokens** | **0** |
| **Total Output Tokens** | **0** |
| **Average Input Tokens Per Request** | **0.0** |
| **Average Output Tokens Per Request** | **0.0** |
| **Estimated Total Cost** | **$0.0000** |
| **Estimated Per-Request Cost** | **$0.0000** |
| **Total Wall-Clock Runtime** | **4.64 seconds** (0.0089s per request) |
| **Memory Peak RSS** | ~145 MB |

---

## 2. Optional AI-Assisted Subsystem Token & Cost Profile

When running in hybrid AI-assisted mode via `--use-ai` using `Gemini 3.8 Flash (Medium)`:

| Component | Model Name | Estimated Input Tokens / Req | Estimated Output Tokens / Req | Cost Per 1M Tokens (Input) | Cost Per 1M Tokens (Output) | Estimated Cost / Req | Total Estimated Run Cost (518 Cases) |
|---|---|---|---|---|---|---|---|
| **Bounded Investigation Loop** | `Gemini 3.8 Flash (Medium)` | ~1,250 | ~280 | $0.075 | $0.300 | $0.000178 | $0.092 |
| **Deterministic Safety Gate** | Python Native Logic | 0 | 0 | $0.000 | $0.000 | $0.000000 | $0.000 |
| **Total Hybrid Mode** | — | **~1,250** | **~280** | — | — | **~$0.00018** | **~$0.092** |

### Token Breakdown by Tool Interaction (Per Request Average in AI Mode)
- **Identity Lookup (`lookup_identity`)**: ~120 input tokens, ~60 output tokens (PII-masked).
- **Evidence Search (`search_records`)**: ~650 input tokens, ~90 output tokens (inert XML wrappers).
- **Policy Retrieval (`get_policy_rule`)**: ~180 input tokens, ~40 output tokens.
- **Resurrection Check (`inspect_resurrection_paths`)**: ~150 input tokens, ~30 output tokens.
- **Finding Submission (`submit_findings`)**: ~150 input tokens, ~60 output tokens.

---

## 3. Cost-Efficiency & Resource Optimization Rationale

1. **Zero Marginal Operational Cost**:
   By encoding the policy semantics into an explicit deterministic state machine and temporal evidence store, the core audit agent operates completely offline with zero API token consumption and zero recurring cost.
2. **Deterministic Reproducibility**:
   Because LLM generation is inherently non-deterministic across varying temperatures and provider latency windows, delegating final status derivation to [`PostModelSafetyGate`](file:///c:/Users/rahul/OneDrive/Desktop/hackerank%20october%20edition/code/core/verification_engine.py) guarantees 100% reproducible outcomes across repeated evaluations.
3. **High-Throughput Performance**:
   Auditing all 518 cases requires only **4.64 seconds** total execution time, avoiding network latency bottlenecks and API rate limits.
