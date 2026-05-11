import os
from langfuse import Langfuse

_client: Langfuse | None = None


def get_client() -> Langfuse:
    global _client
    if _client is None:
        _client = Langfuse(
            public_key=os.environ.get("LANGFUSE_PUBLIC_KEY", ""),
            secret_key=os.environ.get("LANGFUSE_SECRET_KEY", ""),
            host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        )
    return _client


def trace_agent_action(
    session_id: str,
    agent_name: str,
    action: str,
    input_data: dict,
    output_data: dict,
    tokens_used: int = 0,
) -> None:
    try:
        client = get_client()
        trace = client.trace(name=f"{agent_name}:{action}", session_id=session_id)
        trace.span(
            name=action,
            input=input_data,
            output=output_data,
            metadata={"agent": agent_name, "tokens_used": tokens_used},
        )
    except Exception:
        pass  # observability must never crash the platform
