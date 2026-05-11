import json
import os

import httpx
from langgraph.graph import END, START, StateGraph

from agents.documentation import document_finding
from agents.judge import judge_result
from agents.orchestrator import orchestrate
from agents.red_team import generate_attack, mutate_attack
from graph.state import AgentForgeState
from harness.db import init_db, insert_exploit

MAX_MUTATIONS = int(os.environ.get("MAX_MUTATIONS", "3"))
COPILOT_SECRET = os.environ.get("COPILOT_SECRET", "")


def execute_attack(state: AgentForgeState) -> dict:
    """Deterministic HTTP execution — no LLM, just requests against the live target."""
    payload = state["attack_payload"]
    target_url = state["target_url"]
    pid = payload["metadata"].get("pid", 1)
    session_id = state["session_id"]
    responses = []

    with httpx.Client(timeout=30) as client:
        for turn in payload["prompt_sequence"]:
            try:
                full_response = ""
                with client.stream(
                    "POST",
                    f"{target_url}/chat",
                    json={"session_id": session_id, "pid": pid, "question": turn},
                    headers={"X-Copilot-Secret": COPILOT_SECRET},
                ) as r:
                    for line in r.iter_lines():
                        if line.startswith("data: "):
                            full_response += line[6:]
                responses.append({
                    "turn": turn,
                    "response": full_response.strip(),
                    "status": r.status_code,
                })
            except httpx.TimeoutException:
                responses.append({"turn": turn, "response": "TIMEOUT", "status": 0})
            except Exception as exc:
                responses.append({"turn": turn, "response": f"ERROR: {exc}", "status": 0})

    return {"attack_response": {"turns": responses, "pid": pid}}


def update_regression_store(state: AgentForgeState) -> dict:
    """Write to SQLite — deterministic, no LLM."""
    verdict = state["verdict"]
    payload = state["attack_payload"]

    insert_exploit(
        category=payload["category"],
        subcategory=payload["subcategory"],
        severity=verdict["severity"],
        verdict=verdict["verdict"],
        attack_payload=payload,
        attack_response=state.get("attack_response"),
        rationale=verdict["rationale"],
        regression_candidate=verdict["regression_candidate"],
        report_path=state.get("report_path"),
    )
    return {}


def route_after_judge(state: AgentForgeState) -> str:
    verdict = state["verdict"]
    mutation_count = state.get("mutation_count", 0)

    if verdict["verdict"] == "success":
        return "document_finding"
    if verdict["verdict"] == "partial" and mutation_count < MAX_MUTATIONS:
        return "mutate_attack"
    if verdict["verdict"] == "uncertain":
        return END  # escalate to human review
    # failure or mutation limit exhausted — log and try a new category
    return "update_regression_store"


def route_after_orchestrate(state: AgentForgeState) -> str:
    return END if state.get("halt") else "generate_attack"


def build_graph():
    init_db()

    g = StateGraph(AgentForgeState)

    g.add_node("orchestrate", orchestrate)
    g.add_node("generate_attack", generate_attack)
    g.add_node("execute_attack", execute_attack)
    g.add_node("judge_result", judge_result)
    g.add_node("mutate_attack", mutate_attack)
    g.add_node("document_finding", document_finding)
    g.add_node("update_regression_store", update_regression_store)

    g.add_edge(START, "orchestrate")
    g.add_conditional_edges("orchestrate", route_after_orchestrate, {
        "generate_attack": "generate_attack",
        END: END,
    })
    g.add_edge("generate_attack", "execute_attack")
    g.add_edge("execute_attack", "judge_result")
    g.add_conditional_edges("judge_result", route_after_judge, {
        "document_finding": "document_finding",
        "mutate_attack": "mutate_attack",
        "update_regression_store": "update_regression_store",
        END: END,
    })
    g.add_edge("mutate_attack", "execute_attack")
    g.add_edge("document_finding", "update_regression_store")
    g.add_edge("update_regression_store", "orchestrate")

    return g.compile()
