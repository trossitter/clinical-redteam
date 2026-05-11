import os
import uuid

from dotenv import load_dotenv

load_dotenv()

from graph.graph import build_graph  # noqa: E402 — must come after load_dotenv


def run_session(session_id: str | None = None) -> dict:
    if session_id is None:
        session_id = str(uuid.uuid4())

    graph = build_graph()

    initial_state = {
        "session_id": session_id,
        "target_url": os.environ.get("TARGET_URL", "https://clinicalcopilot.org/copilot"),
        "attack_category": "",
        "coverage_summary": {},
        "budget_tokens_remaining": int(os.environ.get("SESSION_BUDGET_TOKENS", "100000")),
        "iteration_count": 0,
        "mutation_count": 0,
        "max_mutations": int(os.environ.get("MAX_MUTATIONS", "3")),
        "attack_payload": None,
        "attack_response": None,
        "verdict": None,
        "report_id": None,
        "report_path": None,
        "pending_human_review": False,
        "halt": False,
        "halt_reason": None,
        "messages": [],
    }

    target = initial_state["target_url"]
    print(f"AgentForge [{session_id[:8]}] starting — target: {target}\n")

    final_state = initial_state.copy()
    for step in graph.stream(initial_state, stream_mode="updates"):
        if not step:
            continue
        node = list(step.keys())[0]
        update = step[node]
        if not update:
            continue
        final_state.update(update)
        display = {k: v for k, v in update.items() if v is not None and k != "messages"}
        if display:
            print(f"[{node}]", display)

    print(f"\nAgentForge [{session_id[:8]}] complete.")
    return final_state


def main() -> None:
    run_session()


if __name__ == "__main__":
    main()
