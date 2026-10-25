"""First meaningful streamed output is distinct from a transport-only chunk.

SmartBuddy's latency observer consumes this field to split model wait from generation.
"""
from unittest.mock import MagicMock, patch

import pytest
from tests.agent import test_first_chunk_at_hook as stream_tests
from tests.agent.test_first_chunk_at_hook import _make_stream_chunk, _run_with_hooks
from tests.agent.test_run_agent import _mock_response


@pytest.fixture(name="agent")
def _agent_fixture():
    return stream_tests.agent.__wrapped__()


def test_first_delta_is_stamped_after_empty_chunk_and_forwarded(agent):
    agent.stream_delta_callback = lambda text: None
    first = []

    def chunks():
        yield _make_stream_chunk()  # role/metadata is not a token
        first.append(getattr(agent, "_last_api_first_delta_at", None))
        yield _make_stream_chunk(content="hello")
        yield _make_stream_chunk(finish_reason="stop", model="test-model")

    client = MagicMock()
    client.chat.completions.create.return_value = chunks()
    with patch.object(agent, "_create_request_openai_client", return_value=client), \
            patch.object(agent, "_close_request_openai_client"):
        result, post = _run_with_hooks(agent)
    assert result["final_response"] == "hello"
    assert first == [None]
    assert post[0]["first_delta_at"] >= post[0]["first_chunk_at"]
    assert post[0]["first_delta_at"] <= post[0]["ended_at"]


def test_non_streamed_attempt_does_not_reuse_previous_first_delta(agent):
    agent._last_api_first_delta_at = 123.0
    agent.client.chat.completions.create.return_value = _mock_response(content="hello")
    _, post = _run_with_hooks(agent)
    assert post[0]["first_delta_at"] is None
