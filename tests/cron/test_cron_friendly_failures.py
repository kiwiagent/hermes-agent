"""kiwiagent: end-user friendly cron failure delivery (cron.friendly_failures).

SmartBuddy users are not operators. With ``cron.friendly_failures: true``:
  - a failing job notifies only on the FIRST failure of a streak, not every tick
  - after ``_FRIENDLY_FAILURE_PAUSE_AFTER`` consecutive failures it is paused,
    with one final notice
  - the text is plain language (Chinese if the job is Chinese), no raw errors
With the flag off, upstream behaviour is unchanged.
"""
import pytest

import cron.scheduler as s
from cron.jobs import create_job, get_job, mark_job_run, pause_job, resume_job


@pytest.fixture()
def tmp_cron_dir(tmp_path, monkeypatch):
    """Redirect cron storage to a temp directory."""
    monkeypatch.setattr("cron.jobs.CRON_DIR", tmp_path / "cron")
    monkeypatch.setattr("cron.jobs.JOBS_FILE", tmp_path / "cron" / "jobs.json")
    monkeypatch.setattr("cron.jobs.OUTPUT_DIR", tmp_path / "cron" / "output")
    return tmp_path


def _patch_failing_run(monkeypatch, *, friendly, error="RuntimeError: HTTP 400: boom"):
    """Make run_job fail with ``error`` and capture delivered content + pauses."""
    delivered = []
    paused = []

    monkeypatch.setattr(s, "load_config", lambda: {"cron": {"friendly_failures": friendly}})
    monkeypatch.setattr(s, "run_job", lambda job, *, defer_agent_teardown=None: (False, "out", "", error))
    monkeypatch.setattr(s, "save_job_output", lambda jid, out: "/tmp/out.txt")
    monkeypatch.setattr(s, "_deliver_result",
                        lambda job, content, adapters=None, loop=None: delivered.append(content))
    monkeypatch.setattr(s, "mark_job_run", lambda jid, ok, err=None, delivery_error=None: None)
    monkeypatch.setattr(s, "pause_job", lambda jid, reason=None: paused.append((jid, reason)))
    return delivered, paused


def _job(streak=0, name="Ballet Tuesday", prompt="Remind me about ballet", kind="cron"):
    schedule = {"kind": kind, "expr": "45 16 * * 2"} if kind == "cron" else {"kind": "once"}
    return {"id": "j1", "name": name, "prompt": prompt, "schedule": schedule,
            "failure_streak": streak}


# ---------------------------------------------------------------------------
# failure_streak bookkeeping (cron/jobs.py)
# ---------------------------------------------------------------------------

class TestFailureStreak:
    def test_mark_job_run_failure_increments_streak(self, tmp_cron_dir):
        job = create_job(prompt="p", schedule="every 1h")

        mark_job_run(job["id"], False, "boom")
        mark_job_run(job["id"], False, "boom")

        assert get_job(job["id"])["failure_streak"] == 2

    def test_mark_job_run_success_resets_streak(self, tmp_cron_dir):
        job = create_job(prompt="p", schedule="every 1h")
        mark_job_run(job["id"], False, "boom")

        mark_job_run(job["id"], True)

        assert get_job(job["id"])["failure_streak"] == 0

    def test_resume_job_resets_streak(self, tmp_cron_dir):
        job = create_job(prompt="p", schedule="every 1h")
        mark_job_run(job["id"], False, "boom")
        pause_job(job["id"])

        resume_job(job["id"])

        assert get_job(job["id"])["failure_streak"] == 0


# ---------------------------------------------------------------------------
# Delivery policy (cron/scheduler.py run_one_job)
# ---------------------------------------------------------------------------

class TestFriendlyDeliveryPolicy:
    def test_run_one_job_FlagOff_DeliversRawSummaryEveryTime(self, monkeypatch):
        delivered, paused = _patch_failing_run(monkeypatch, friendly=False)

        s.run_one_job(_job(streak=5))

        assert len(delivered) == 1
        assert "Cron 'Ballet Tuesday' failed" in delivered[0]
        assert paused == []

    def test_run_one_job_FirstFailure_DeliversFriendlyMessage(self, monkeypatch):
        delivered, paused = _patch_failing_run(monkeypatch, friendly=True)

        s.run_one_job(_job(streak=0))

        assert len(delivered) == 1
        assert "Ballet Tuesday" in delivered[0]
        assert "HTTP 400" not in delivered[0]
        assert "Cron" not in delivered[0]
        assert paused == []

    def test_run_one_job_RepeatedFailure_SuppressesDelivery(self, monkeypatch):
        delivered, paused = _patch_failing_run(monkeypatch, friendly=True)

        s.run_one_job(_job(streak=1))

        assert delivered == []
        assert paused == []

    def test_run_one_job_ThresholdReached_PausesAndNotifiesOnce(self, monkeypatch):
        delivered, paused = _patch_failing_run(monkeypatch, friendly=True)

        s.run_one_job(_job(streak=s._FRIENDLY_FAILURE_PAUSE_AFTER - 1))

        assert len(paused) == 1 and paused[0][0] == "j1"
        assert len(delivered) == 1
        assert "paused" in delivered[0]

    def test_run_one_job_FriendlySuccess_DeliversResponseUnchanged(self, monkeypatch):
        delivered, _ = _patch_failing_run(monkeypatch, friendly=True)
        monkeypatch.setattr(s, "run_job",
                            lambda job, *, defer_agent_teardown=None: (True, "out", "Ballet at 5pm!", None))

        s.run_one_job(_job(streak=2))

        assert delivered == ["Ballet at 5pm!"]


# ---------------------------------------------------------------------------
# Wording (cron/scheduler.py _friendly_cron_failure_message)
# ---------------------------------------------------------------------------

class TestFriendlyWording:
    def test_missing_script_AsksUserToDescribeTask(self):
        msg = s._friendly_cron_failure_message(
            _job(name="Gmail New Email Monitor"),
            "Script not found: /opt/data/scripts/check_gmail.py")

        assert "Gmail New Email Monitor" in msg
        assert "missing" in msg
        assert "/opt/data" not in msg

    @pytest.mark.parametrize("error", [
        "RuntimeError: HTTP 400: /chat/completions: Invalid model name passed in model=qwen-plus.",
        "Skipped to prevent unintended spend: global inference config drifted since this job was created",
        "HTTP 429 rate limit",
        "ReadTimeout: timed out",
    ])
    def test_platform_side_errors_SayTemporaryProblemOnMySide(self, error):
        msg = s._friendly_cron_failure_message(_job(), error)

        assert "temporary problem on my side" in msg
        assert "qwen" not in msg and "HTTP" not in msg

    def test_unknown_error_IsGenericWithoutRawText(self):
        msg = s._friendly_cron_failure_message(_job(), "ZeroDivisionError: division by zero")

        assert "didn't run successfully" in msg
        assert "ZeroDivisionError" not in msg

    def test_recurring_job_PromisesRetry(self):
        msg = s._friendly_cron_failure_message(_job(kind="cron"), "HTTP 429")

        assert "next scheduled time" in msg

    def test_one_shot_job_DoesNotPromiseRetry(self):
        msg = s._friendly_cron_failure_message(_job(kind="once"), "HTTP 429")

        assert "next scheduled time" not in msg

    def test_chinese_job_GetsChineseMessage(self):
        msg = s._friendly_cron_failure_message(
            _job(name="芭蕾课提醒", prompt="提醒我周二芭蕾课"), "HTTP 429")

        assert "芭蕾课提醒" in msg
        assert "我这边临时出了点问题" in msg

    def test_paused_message_ExplainsHowToResume(self):
        msg = s._friendly_cron_failure_message(_job(), "HTTP 429", paused=True)

        assert "paused" in msg
        assert 'resume Ballet Tuesday' in msg

    def test_paused_message_Chinese(self):
        msg = s._friendly_cron_failure_message(
            _job(name="芭蕾课提醒", prompt="提醒我"), "HTTP 429", paused=True)

        assert "暂停" in msg
        assert "恢复芭蕾课提醒" in msg
