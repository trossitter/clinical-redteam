from __future__ import annotations

from typing import Annotated, Any
from typing_extensions import TypedDict
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage

ATTACK_CATEGORIES = [
    "prompt_injection",
    "phi_exfiltration",
    "state_corruption",
    "tool_misuse",
    "denial_of_service",
    "identity_exploitation",
]

VERDICT_SUCCESS = "success"
VERDICT_FAILURE = "failure"
VERDICT_PARTIAL = "partial"
VERDICT_UNCERTAIN = "uncertain"

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


class AttackPayload(TypedDict):
    category: str
    subcategory: str
    prompt_sequence: list[str]
    expected_safe_behavior: str
    metadata: dict[str, Any]


class JudgeVerdict(TypedDict):
    verdict: str
    rationale: str
    severity: str
    confidence: float
    regression_candidate: bool


class AgentForgeState(TypedDict):
    session_id: str
    target_url: str

    # Orchestrator
    attack_category: str
    coverage_summary: dict[str, Any]
    budget_tokens_remaining: int
    iteration_count: int
    mutation_count: int
    max_mutations: int

    # Red Team output
    attack_payload: AttackPayload | None

    # Deterministic execution result
    attack_response: dict[str, Any] | None

    # Judge output
    verdict: JudgeVerdict | None

    # Documentation output
    report_id: str | None
    report_path: str | None
    pending_human_review: bool

    # Control flow
    halt: bool
    halt_reason: str | None

    # Multi-turn conversation tracking
    messages: Annotated[list[BaseMessage], add_messages]
