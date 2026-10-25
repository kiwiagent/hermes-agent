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


def test_retry_exposes_a_fresh_attempt_start_without_changing_logical_start(agent):
    class RateLimitError(Exception):
        status_code = 429

        def __str__(self):
            return "Error code: 429 - Rate limit exceeded."

    starts = []
    responses = iter([RateLimitError(), _mock_response(content="recovered")])

    def provider(**kwargs):
        starts.append(getattr(agent, "_last_api_attempt_started_at", None))
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    agent.client.chat.completions.create.side_effect = provider
    with patch("run_agent.time.sleep", return_value=None):
        result, post = _run_with_hooks(agent)
    assert result["final_response"] == "recovered"
    assert len(starts) == 2
    assert starts[0] < starts[1]
    assert post[0]["attempt_started_at"] == starts[1]
    assert post[0]["started_at"] < starts[0]


def test_completed_response_replay_does_not_claim_a_streamed_first_token(agent):
    agent.stream_delta_callback = lambda text: None
    client = MagicMock()
    client.chat.completions.create.return_value = _mock_response(content="full response")
    with patch.object(agent, "_create_request_openai_client", return_value=client), \
            patch.object(agent, "_close_request_openai_client"):
        result, post = _run_with_hooks(agent)
    assert result["final_response"] == "full response"
    assert agent._disable_streaming is True
    assert post[0]["first_delta_at"] is None
