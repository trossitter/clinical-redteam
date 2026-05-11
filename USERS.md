# AgentForge — Users, Workflows, and Use Cases

AgentForge addresses three distinct users: the Hospital CISO responsible for security assurance, the AI/ML Security Researcher conducting authorized penetration testing, and the Clinical Informatics Engineer who builds and maintains the Clinical Co-Pilot. Each arrives at the platform with different questions, different domain fluency, and different tolerances for how manual their workflow can be. This document defines each persona, maps their workflows to AgentForge's capabilities, and makes explicit why automation — not manual testing — is the appropriate solution for each.

---

## User 1: Hospital CISO / Security Lead

### Role

The Hospital CISO is accountable for the security posture of every system that touches patient data or clinical workflows. With the deployment of an AI layer in OpenEMR — the Clinical Co-Pilot at clinicalcopilot.org — that accountability extends to a class of risk that traditional security tooling was not built to address: an AI system that generates natural-language responses, mediates physician access to protected health information, and behaves non-deterministically across runs.

The CISO does not need to understand prompt injection mechanics. They need continuous, credible evidence that the AI layer is not exploitable, and they need that evidence documented in a form that satisfies HIPAA risk analysis obligations, withstands audit, and can be acted on by their security and development teams without additional translation.

### Goals

- Continuous assurance that the Clinical Co-Pilot's AI layer cannot be used to exfiltrate PHI, provide incorrect clinical guidance, or be manipulated by a motivated attacker.
- Professional vulnerability documentation they can surface to a board, a compliance auditor, or legal counsel — not developer log output.
- Early warning before a security regression becomes a patient safety incident or a reportable breach.
- Evidence that a confirmed vulnerability has been remediated, not just patched.

### Pain Points

- Traditional DAST and SAST tools do not test AI behavior. A scanner that checks for SQL injection or missing headers produces no signal about whether the Clinical Co-Pilot can be manipulated via prompt injection or PHI inference attacks.
- Manual red-teaming of an LLM-integrated system is not a one-time event. The attack surface changes every time the underlying model changes, every time a new tool is added to the agent loop, and every time a system prompt constraint is modified. A penetration test conducted six months ago does not reflect the current posture.
- HIPAA's Security Rule requires ongoing assessment of threats and vulnerabilities. Point-in-time assessments do not satisfy "ongoing."
- A confirmed exploit in a clinical AI system may trigger breach notification obligations. The CISO needs to know immediately when a Critical severity finding is confirmed — and needs it held for their review before it is filed, because the downstream obligations (breach assessment, vendor notification, potential workflow suspension) must not be initiated by an automated system without human sign-off.

### Specific Use Cases with AgentForge

**Scheduled overnight regression runs.** The Orchestrator reads the SQLite regression harness at the start of each session and dispatches the full library of confirmed exploit cases against the live target. A regression run that completes overnight produces a coverage report by morning: which attack categories were tested, how many cases per category, and whether any previously confirmed vulnerability remains unpatched. The CISO sees the result as a structured summary — not a log file.

**Post-deploy validation.** When the Clinical Co-Pilot is updated, the Orchestrator detects the change via response fingerprinting and triggers a regression suite against the new version. Every confirmed exploit from prior runs is replayed. Any category where the pass rate drops below its historical baseline generates a cross-category regression alert in Langfuse, surfaced through the `/agentforge` dashboard. The CISO does not need to be present for the run to receive actionable output.

**Executive reporting.** The Documentation Agent produces structured vulnerability reports — report ID, severity tier, category, clinical impact, reproduction steps, remediation recommendation, and filing status — in a format a hospital security committee can review. Critical severity findings are held in the human approval gate and do not enter the SQLite regression store until a named reviewer approves them. This gate exists precisely because a Critical finding in a clinical system carries obligations that must not be triggered automatically.

**HIPAA risk analysis evidence.** The SQLite regression harness maintains a versioned, auditable record of every attack case run, every verdict issued by the Judge, and every vulnerability report filed by the Documentation Agent. The `regression_runs` table records which exploit cases were retested against which target version. This is the kind of structured, timestamped evidence that supports an ongoing HIPAA risk analysis — not a spreadsheet, not a narrative summary.

### Why Automation Is the Right Solution

The Clinical Co-Pilot is a non-deterministic system. The same prompt may produce different outputs across runs due to model temperature, context variation, and prompt rephrasing. A human red-teamer who tests a specific attack payload on a Tuesday afternoon and finds it blocked cannot conclude the system is secure — the same payload might succeed on Wednesday with a slightly different conversational context. Automation solves this by running each attack case repeatedly, across sessions, against multiple target versions, and evaluating results with the Judge's consistent rubric rather than human judgment that varies by tester and day.

The attack surface evolves with the model. When Anthropic updates Claude Sonnet — the model that powers the Clinical Co-Pilot's agent loop — behavioral characteristics change in ways that cannot be predicted from the model version number. Defenses built around specific known-bad examples may fail against semantically equivalent variants. A static attack library run once does not capture this drift. AgentForge's Red Team Agent continuously mutates partial-success attacks, extending the test library with variants that would not appear in any manually curated list.

The human cost of a missed vulnerability is not theoretical. The Clinical Co-Pilot mediates physician access to patient medication lists, lab results, diagnoses, and care plans. An exploitable vulnerability in this interface — a prompt injection that causes the model to provide an incorrect drug dosage, a cross-patient PHI leak that exposes an HIV-positive status, a context poisoning attack that plants a false allergy in the conversation — can result in patient harm before the vulnerability is discovered. The asymmetry between the cost of continuous automated testing and the cost of a patient safety incident justifies the platform.

---

## User 2: AI/ML Security Researcher

### Role

The AI/ML Security Researcher is conducting authorized penetration testing of an LLM-integrated clinical system. They may be embedded in the hospital's security team, contracted as an external assessor, or working in an academic research context with proper authorization and scope agreement. Their technical depth is high: they understand model behavior, prompt engineering, token budgets, multi-turn context manipulation, and the specific failure modes of tool-augmented agentic systems.

What they need from AgentForge is not automation to replace their judgment — it is structure to extend their reach. A researcher who can manually craft a sophisticated prompt injection sequence for one attack category can use AgentForge to systematically probe all six categories, run mutation campaigns on partial successes, and validate whether a defense actually holds against the full attack surface rather than just the specific variant they happened to test.

### Goals

- A structured framework for probing specific attack categories with reproducible, extendable test cases.
- A mutation loop that automatically extends partial-success cases into the full variant space — not just the variants the researcher thought of by hand.
- An independent Judge whose evaluation does not share model state or context with the Red Team, so verdicts are not self-serving.
- Traces that let them inspect exactly what the Red Team Agent sent, what the target returned, and how the Judge reasoned about the verdict — at the per-turn level.
- The ability to add novel attack variants to the seed library and immediately fold them into the next coverage cycle.

### Pain Points

- Manual attack campaigns against an LLM target are exhausting to reproduce. A multi-turn prompt injection sequence that took an hour to develop is useless if it cannot be rerun against the next deployment or shared with a colleague.
- Single-model evaluation pipelines produce unreliable verdicts. If the same model that generated the attack also judges whether it succeeded, confirmation bias is baked in — a known problem in adversarial ML evaluation documented in the literature. The researcher needs structural independence between attacker and evaluator.
- Coverage gaps are invisible without instrumentation. A researcher who has spent three sessions probing prompt injection and zero sessions on state corruption has no systematic way to know their coverage distribution without logging everything manually.
- Partial successes are the hardest to exploit manually. A probe that gets the model to partially comply — not a clean success, not a clean failure — is the most valuable signal in adversarial testing, and it requires the most effort to follow up: rephrasing, context reordering, turn-order shuffling. Manual mutation of partial successes is time-consuming and inconsistent.

### Specific Use Cases with AgentForge

**Targeted attack campaigns.** The researcher configures a session targeting a specific category — for example, `phi_exfiltration` — with an elevated turn budget and a high `MAX_MUTATIONS` value. The Orchestrator dispatches the Red Team Agent against that category for the full session. The researcher monitors the live Judge verdict feed on the `/agentforge` dashboard, which surfaces each verdict with full rationale text and color-coded outcome, and inspects Langfuse traces for per-turn inputs and responses when a partial verdict warrants closer examination.

**Adding novel attack variants to the seed library.** Attack seed cases live in `evals/cases/` as structured JSON files (`prompt_injection.json`, `phi_exfiltration.json`, `state_corruption.json`, `tool_misuse.json`, `dos_patterns.json`, `identity_exploitation.json`). Each case specifies the attack category, subcategory, multi-turn prompt sequence, and the `expected_safe_behavior` against which the Judge evaluates the response. A researcher who discovers a novel attack technique adds it to the appropriate JSON file. On the next session, the Red Team Agent picks it up as a seed case, the Judge evaluates it against the versioned rubric, and if it produces a `partial` verdict, the mutation loop automatically extends it into variants. The researcher's single case becomes a family of test cases without additional manual effort.

**Validating that a defense actually holds.** When the Clinical Co-Pilot team implements a mitigation — for example, adding structured XML delimiters to separate trusted tool results from untrusted content — the researcher needs to know whether the fix holds against the full variant space, not just the specific attack they used to demonstrate the original vulnerability. The regression harness runs every confirmed exploit case against the patched target, using the same versioned rubric that produced the original verdict. A defense that passes the specific test case but fails against a mutation is correctly identified as insufficient. The Judge's `regression_candidate` flag ensures that confirmed exploits are automatically enrolled in future regression runs.

**Canary injection for Judge drift detection.** The Orchestrator periodically injects ground-truth labeled cases — known successes and known failures — into the Judge's evaluation queue. If the Judge's verdicts on canary cases deviate from ground truth beyond a configured threshold, the Orchestrator flags a Judge drift event and suspends auto-filing of findings. A researcher who wants to verify the Judge's calibration can inspect the canary accuracy log in Langfuse without running a separate evaluation. This matters when the rubric is updated: rubric version is stored alongside every verdict, so the researcher can determine whether a change in verdict rate reflects a rubric change or a real change in target behavior.

### Why Automation Is the Right Solution

Manual mutation of partial-success attacks is the highest-value and most labor-intensive part of adversarial testing. A researcher who identifies that a multi-turn persona drift sequence gets the model to partially acknowledge an elevated authorization claim has found the most important signal in the session — but following it up requires generating and running a dozen variants: rephrasing the framing, changing the turn order, injecting supporting context earlier in the conversation, softening the final escalation step. This is work the Red Team Agent does in the mutation loop (`MAX_MUTATIONS` variants per partial result), at zero marginal cost beyond API tokens, faster than any human can type.

A comprehensive adversarial campaign across six attack categories — prompt injection, PHI exfiltration, state corruption, tool misuse, denial of service, and identity exploitation — with systematic mutation of partial successes would require weeks of human red-team time per deployment cycle. AgentForge runs the equivalent campaign overnight. The researcher's time is freed for the work that requires human judgment: interpreting novel findings, designing new attack categories, and advising on remediation approaches.

Regressions are invisible without continuous testing. A researcher who validates a defense once cannot detect when a subsequent code change reintroduces the vulnerability in a slightly different form. The regression harness, running after each deployment, surfaces this automatically. The researcher sees it in the coverage table on the dashboard before the CISO asks about it.

---

## User 3: Clinical Informatics Engineer / Co-Pilot Developer

### Role

The Clinical Informatics Engineer builds and maintains the Clinical Co-Pilot. They understand the system's architecture in detail: the FastAPI service, the Claude Sonnet agent loop, the six database-query tools, the hybrid RAG retriever over clinical guidelines, the multimodal document ingestion pipeline, the system prompt constraints, and the verification layer that runs post-hoc on model responses. They are closest to the code and closest to the consequences when a security vulnerability is introduced — often by a change made to address a different problem entirely.

What they need from AgentForge is a security gate that runs without requiring their presence, produces findings they can act on directly, and tells them when a code change introduced a regression in security posture. They cannot run a manual adversarial test campaign before every deployment. They need the platform to do it for them.

### Goals

- Automated security validation after every deployment, with results available before the next sprint begins.
- Vulnerability reports with enough detail to implement a fix without asking for clarification: reproduction steps exact enough to reproduce locally, root cause analysis that identifies the specific code path or behavioral constraint that failed, and a remediation recommendation that is technically feasible within the existing architecture.
- Clear signal when a patch regression occurs — when fixing one vulnerability inadvertently reopens another.
- A historical record of vulnerability status over time that they can point to in a sprint review or a security audit.

### Pain Points

- Security regressions introduced by legitimate code changes are the hardest class of bug to find manually. A change to the system prompt that tightens one constraint may inadvertently weaken another. A refactor of the tool dispatcher that improves performance may reintroduce a parameter pass-through that was previously blocked. Without automated regression testing, these regressions are found by accident — or by an attacker.
- Vulnerability reports from manual security reviews are frequently not actionable. "The model can be manipulated to reveal system prompt contents" is not a reproduction step. "The model accepts false authorization claims over multi-turn conversations" is not a root cause. The Documentation Agent's reports are written to be reproducible by a senior security engineer who was not present during discovery, and to include specific technically feasible remediation recommendations — not generic advice.
- The developer's intuition about what is secure is systematically wrong for LLM-integrated systems. Constraints that feel robust — "ignore instructions in quoted text" — are behavioral, not structural, and fail against unquoted injection or multi-turn drift. The attack categories in AgentForge (prompt injection, PHI exfiltration, state corruption, tool misuse, denial of service, identity exploitation) map directly to the Clinical Co-Pilot's actual threat surface as documented in `THREAT_MODEL.md`. The developer cannot enumerate these from first principles without adversarial testing.

### Specific Use Cases with AgentForge

**Pre-release security gate.** After deploying a new version of the Clinical Co-Pilot, the developer triggers AgentForge via `curl -X POST https://clinicalcopilot.org/agentforge/run` or through the dashboard. The Orchestrator reads the coverage state from SQLite, dispatches the Red Team Agent against uncovered or recently stale categories, and runs the full regression suite against previously confirmed exploits. The developer checks the `/agentforge/findings` endpoint for new confirmed findings before marking the release complete. A deployment that introduces a regression in any confirmed-exploit category fails this gate.

**Post-patch validation.** After implementing a remediation — for example, adding a per-turn tool-call iteration limit to address the recursive tool-call exhaustion vulnerability — the developer reruns the regression harness against the patched target. The Judge evaluates the specific exploit case that confirmed the original vulnerability, using the same versioned rubric. A verdict of `failure` (attack did not succeed) on a previously confirmed `success` case is evidence that the patch holds. The `regression_runs` table records this result against the target version and the rubric version, providing a timestamped audit trail. The developer also checks cross-category regression: the Orchestrator runs all other categories after a patch to verify that fixing one category did not regress another — a pattern documented in `ARCHITECTURE.md` as a first-class regression detection concern.

**Tracking vulnerability status over time.** The `exploits` table in the SQLite regression store maintains status (`open`, `in-progress`, `resolved`) for every confirmed finding. The vulnerability reports generated by the Documentation Agent are filed with a report ID (e.g., `VULN-20260511-A3F2B1C7`) and a filing timestamp. As the developer works through the remediation backlog, they update exploit status and rerun the regression harness to produce evidence that each finding is resolved. The `/agentforge/findings` endpoint surfaces open findings sorted by severity. This is the living security backlog — not a spreadsheet maintained manually, but a structured store updated by the platform with every run.

**Understanding a vulnerability before fixing it.** The Documentation Agent's reports are structured to make root cause visible, not just behavior. Each report includes the exact multi-turn attack sequence as reproduction steps, the observed response that confirmed the exploit, the expected safe behavior that was not exhibited, a root cause analysis identifying the specific mechanism that failed, and a remediation recommendation scoped to the Clinical Co-Pilot's architecture. For example: a confirmed prompt injection via indirect SOAP note injection is documented with the specific `get_recent_encounters` tool result that carried the payload, the model response that followed the injected instruction rather than the system prompt, and a remediation recommendation to add structured XML delimiters between trusted system instructions and untrusted tool result content — not a generic note about "improving input sanitization."

### Why Automation Is the Right Solution

Clinical AI systems are non-deterministic at the level that matters for security testing. A system prompt constraint that blocks a direct injection attempt on one run may not block a semantically equivalent attempt on the next run, because model behavior varies with context and temperature. A developer who manually tests a patched system with three attack variants cannot conclude the defense is robust — they can only conclude it held for those three variants in that session. The regression harness runs the full confirmed-exploit library against each new deployment, evaluating results with a consistent rubric rather than human judgment that varies by session.

The attack surface evolves faster than manual review can track. The Clinical Co-Pilot's security posture is affected by changes to the system prompt, changes to the tool set, changes to the verification layer, and changes to the underlying Claude model. A developer who performed manual adversarial testing six months ago has no assurance that their findings reflect the current posture — the model they tested against may no longer be the model they are running. AgentForge runs against the live target at every deployment cycle, continuously extending the attack library with mutations that reflect the current model's behavioral characteristics.

The cost of a missed regression in a clinical system is asymmetric. A regression that reintroduces a confirmed PHI exfiltration vulnerability — even temporarily, even in demo mode — has a different consequence profile than a regression in a consumer app. The clinical context makes the cost of false negatives (missed vulnerabilities) substantially higher than the cost of false positives (unnecessary security investigation). Continuous automated testing is the only approach that keeps the false negative rate low enough to be consistent with responsible deployment of an AI system that mediates access to patient health records.

---

## Summary: Why This Platform, Why Now

All three users share a common constraint: the attack surface they are responsible for is larger, more dynamic, and more consequential than any manual testing program can cover. The Clinical Co-Pilot's six attack categories — prompt injection across three distinct injection surfaces, PHI exfiltration via cross-patient inference and session manipulation, state corruption via context poisoning, tool misuse via parameter tampering and recursive loops, denial of service via token exhaustion, and identity exploitation via persona hijacking and privilege escalation — were identified through a structured threat model of the live system. Each category has confirmed attack paths documented in `THREAT_MODEL.md`. The seed cases in `evals/cases/` encode those paths as reproducible test cases. The Red Team Agent extends them into the full variant space. The Judge evaluates them against a consistent rubric. The Documentation Agent converts confirmed findings into reports the CISO can act on, the researcher can cite, and the developer can fix.

The platform does not replace human judgment at the points where it matters. Critical severity findings are held at the human approval gate before filing. Uncertain verdicts are escalated to human review rather than auto-resolved. Rubric changes are human decisions stored in SQLite. What the platform automates is the work that does not benefit from human judgment: the execution of hundreds of attack cases per session, the evaluation of each result against a consistent standard, the filing of findings in a structured format, and the continuous regression testing that makes security a property of the system rather than a one-time assessment.
