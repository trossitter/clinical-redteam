# AgentForge — AI Cost Analysis

**Adversarial AI Security Platform — Gauntlet AI Week 3**
**Date:** May 12, 2026

---

## Summary

AgentForge uses a hybrid model architecture that keeps cost-per-attack-cycle low by design: the high-volume component (Red Team attack generation) runs on local or free-tier infrastructure, while frontier model API calls are reserved for the roles that require their reasoning quality (Judge, Orchestrator, Documentation). This asymmetry is not an optimization afterthought — it is a deliberate architectural decision driven by both cost and capability constraints (frontier models refuse offensive security workflows; local/Groq models do not).

---

## Actual Development Spend

| Component | Model | Estimated tokens consumed | Estimated cost |
|---|---|---|---|
| Judge evaluations | Claude Sonnet 4.6 | ~180,000 input / ~45,000 output | ~$1.22 |
| Orchestrator cycles | Claude Sonnet 4.6 | ~120,000 input / ~30,000 output | ~$0.81 |
| Documentation Agent | Claude Sonnet 4.6 | ~40,000 input / ~16,000 output | ~$0.36 |
| Red Team generation | Groq llama-3.3-70b (free tier) | — | $0.00 |
| Red Team generation | Local Ollama Qwen2.5:32b | — | $0.00 |
| HTTP execution | Python httpx | — | $0.00 |
| **Total API spend** | | | **~$2.39** |

**Actual dev-time Claude API spend: approximately $2–4** (estimate based on session count × average cycle depth; exact invoice not available as sessions share an API key with Week 2 Clinical Co-Pilot development).

**Groq spend: $0.00** — all Red Team inference consumed from Groq's free tier (14,400 requests/day).

**Ollama spend: $0.00** — Qwen2.5:32b runs locally.

---

## Per-Run Cost Model (Deployed, Cloud Mode)

One "run" = one full attack cycle: Orchestrator → Red Team → Execute → Judge, with Documentation Agent firing only on confirmed exploits (roughly 1 in 5 cycles at current hit rate).

| Agent | Model | Avg tokens in | Avg tokens out | Cost per call |
|---|---|---|---|---|
| Orchestrator | Claude Sonnet 4.6 | 800 | 200 | ~$0.0051 |
| Red Team | Groq llama-3.3-70b | 1,200 | 400 | $0.0000 (free tier) |
| Execute | HTTP (httpx) | — | — | $0.0000 |
| Judge | Claude Sonnet 4.6 | 1,400 | 350 | ~$0.0094 |
| Documentation (20% of cycles) | Claude Sonnet 4.6 | 2,800 × 0.2 | 900 × 0.2 | ~$0.0043 |
| **Total per cycle** | | | | **~$0.019** |

*Claude Sonnet 4.6 pricing: $3.00/1M input tokens, $15.00/1M output tokens.*

---

## Projected Production Costs at Scale

| Scale | Est. cost (cloud mode) | Est. cost (optimized) | Architectural changes required |
|---|---|---|---|
| **100 runs** | ~$1.90 | ~$1.90 | None — current architecture handles this comfortably |
| **1,000 runs** | ~$19 | ~$8 | Async Judge queue to parallelise evaluation; batch Orchestrator context reads |
| **10,000 runs** | ~$190 | ~$25 | Swap Judge to Claude Haiku 4.5 (10× cheaper, acceptable for deterministic rubric); cache Orchestrator coverage reads |
| **100,000 runs** | ~$1,900 | ~$80 | Fine-tune a Judge model on ground-truth verdicts; replace Groq with self-hosted inference (Ollama on GPU server) for zero marginal cost at volume; shard SQLite to PostgreSQL for concurrent writes |

**The "optimized" column is not speculative.** Each transition is achievable within the current architecture:

- **Haiku swap (10K):** One env var change (`JUDGE_MODEL=claude-haiku-4-5`). The Judge rubric is versioned and deterministic — Haiku handles structured evaluation tasks at this level of specificity.
- **Fine-tuned Judge (100K):** The `regression_candidate` flag already tags ground-truth cases for this purpose. After ~500 labeled verdicts, a fine-tuned classifier on a smaller model (or a deterministic rules engine) replaces Claude for verdict evaluation entirely.
- **Self-hosted inference (100K):** Ollama running on a RunPod A100 pod serves both Red Team and a fine-tuned Judge. Marginal cost per run approaches $0 beyond infrastructure amortization.

---

## Cost Drivers and Control Levers

### What makes a run expensive
1. **Long Orchestrator context** — coverage reports grow as cases accumulate. Mitigation: summarise coverage into a fixed-size digest rather than passing the full table.
2. **High mutation depth** — `MAX_MUTATIONS=3` means a partial success can trigger 3 additional Judge calls. Mitigation: reduce to 2 for high-volume regression runs; reserve depth-3 for novel attack discovery campaigns.
3. **Documentation Agent on false positives** — a Judge error that produces a false `success` verdict triggers a full Documentation Agent run. Mitigation: confidence threshold (currently implicit); add explicit `confidence > 0.85` gate before routing to Documentation.

### What keeps runs cheap
- **Red Team is always $0** — Groq free tier or local Ollama. The highest-volume agent is the cheapest.
- **Execute is always $0** — HTTP requests have no AI cost.
- **Documentation fires rarely** — approximately 1 in 5 cycles at current attack success rates. At scale on a hardened system, this rate drops further.

---

## Cost vs. Alternative Approaches

| Approach | Cost at 10K runs | Limitation |
|---|---|---|
| AgentForge (current) | ~$190 | Requires Anthropic API for Judge/Orchestrator |
| AgentForge (optimised, Haiku Judge) | ~$25 | Slight accuracy reduction on novel attack categories |
| Manual red-team engagement | ~$15,000–50,000 | One-time; no regression; does not scale with deployment cadence |
| Commercial LLM security scanning (e.g. Lakera, Garak) | ~$500–2,000/month SaaS | Generalised; not tailored to clinical workflow attack surface |
| Static prompt injection test suite | ~$0 | Does not mutate; does not adapt; misses multi-turn attacks entirely |

AgentForge at 10K runs costs less than one hour of a senior security consultant's time and produces a continuously-updating, reproducible, regression-capable adversarial evaluation suite.

---

## Infrastructure Cost (Non-API)

| Component | Cost |
|---|---|
| DigitalOcean Droplet (2 vCPU / 4 GB, NYC3) | ~$24/month |
| Groq API (Red Team inference) | $0 (free tier sufficient through ~10K runs/day) |
| Langfuse (self-hosted on same droplet) | $0 |
| Domain (clinicalcopilot.org, Cloudflare) | ~$10/year |
| **Total infrastructure** | **~$24/month** |

---

*AgentForge — Week 3, Gauntlet AI — May 2026*
