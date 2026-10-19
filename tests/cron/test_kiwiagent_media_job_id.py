"""kiwiagent: a cron delivery's attachments carry the job id, like its text.

SmartBuddy files a reply under the scheduled job only when job_id is in the
metadata; without it a job's files landed under whatever the chat did last.
"""
from types import SimpleNamespace

from gateway.config import Platform

from cron.scheduler_delivery import _live_route_metadata


def _target(thread_id=None):
    return SimpleNamespace(
        job={"id": "weekend-job"}, platform=Platform.DISCORD, chat_id="1234", thread_id=thread_id,
        runtime_adapter=None, loop=None, notify_delivery=True,
        origin={}, origin_target=False, origin_user_id=None, is_relay=False,
    )


def test_media_metadata_carries_job_id():
    _thread, route, media = _live_route_metadata(_target())

    assert route["job_id"] == "weekend-job"
    assert media["job_id"] == "weekend-job"


def test_media_in_thread_carries_job_id_and_thread():
    _thread, _route, media = _live_route_metadata(_target(thread_id="77"))

    assert media["job_id"] == "weekend-job"
    assert media["thread_id"] == "77"
