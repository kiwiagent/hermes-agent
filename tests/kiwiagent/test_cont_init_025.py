"""kiwiagent: docker/cont-init.d/025-kiwiagent-api-server config patching.

The script's embedded Python (the ``<<'PY'`` heredoc) is extracted and run
against a temp HERMES_HOME, the same way the container runs it at boot.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(__file__).resolve().parents[2] / "docker" / "cont-init.d" / "025-kiwiagent-api-server"


def _embedded_python() -> str:
    lines = SCRIPT.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.rstrip().endswith("<<'PY'"))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "PY")
    return "\n".join(lines[start + 1:end]) + "\n"


def _run(home: Path, **env_overrides) -> subprocess.CompletedProcess:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HERMES_HOME": str(home),
        "LITELLM_BASE_URL": "http://litellm:4000",
        "LITELLM_API_KEY": "sk-test",
        "HERMES_DEFAULT_MODEL": "deepseek-flash",
        "SMARTBUDDY_AGENT_ID": "8",
    }
    env.update(env_overrides)
    env = {k: v for k, v in env.items() if v is not None}
    return subprocess.run([sys.executable, "-"], input=_embedded_python(), text=True,
                          capture_output=True, env=env, check=True)


@pytest.fixture()
def home(tmp_path):
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"model": {}}))
    return tmp_path


def _write_jobs(home: Path, jobs):
    cron = home / "cron"
    cron.mkdir(exist_ok=True)
    (cron / "jobs.json").write_text(json.dumps({"jobs": jobs, "updated_at": "x"}))


def _read_jobs(home: Path):
    return json.loads((home / "cron" / "jobs.json").read_text())["jobs"]


def _config(home: Path) -> dict:
    return yaml.safe_load((home / "config.yaml").read_text())


class TestCronDeliveryConfig:
    def test_smartbuddy_pod_DisablesWrapAndEnablesFriendlyFailures(self, home):
        _run(home)

        cron = _config(home)["cron"]
        assert cron["wrap_response"] is False
        assert cron["friendly_failures"] is True

    def test_non_smartbuddy_pod_LeavesCronConfigAlone(self, home):
        _run(home, SMARTBUDDY_AGENT_ID=None)

        assert "cron" not in _config(home)


class TestChatDisplayConfig:
    """End users shouldn't see operator notices ("💾 Self-improvement review"
    for memory updates / skill patches — new skills are still announced),
    "⚡ Interrupting current task (iteration 4/90)"), and a follow-up message
    should steer the running task instead of aborting it."""

    def test_smartbuddy_pod_SilencesNoticesAndSteersFollowUps(self, home):
        _run(home)

        display = _config(home)["display"]
        assert display["memory_notifications"] == "new_skills"
        assert display["busy_ack_enabled"] is False
        assert display["busy_input_mode"] == "steer"

    def test_smartbuddy_pod_KeepsOtherDisplayKeys(self, home):
        (home / "config.yaml").write_text(yaml.safe_dump({"model": {}, "display": {"show_reasoning": True}}))

        _run(home)

        assert _config(home)["display"]["show_reasoning"] is True

    def test_non_smartbuddy_pod_LeavesDisplayAlone(self, home):
        _run(home, SMARTBUDDY_AGENT_ID=None)

        assert "display" not in _config(home)


class TestNoDoubleConfirm:
    """The app's New chat already asks "Start a new chat?" before sending /new;
    hermes asking again ("⚠️ Confirm /new … reply /approve") is redundant."""

    def test_smartbuddy_pod_DisablesDestructiveSlashConfirm(self, home):
        _run(home)

        assert _config(home)["approvals"]["destructive_slash_confirm"] is False

    def test_smartbuddy_pod_KeepsOtherApprovalKeys(self, home):
        (home / "config.yaml").write_text(yaml.safe_dump({"model": {}, "approvals": {"mode": "manual"}}))

        _run(home)

        assert _config(home)["approvals"]["mode"] == "manual"

    def test_non_smartbuddy_pod_LeavesApprovalsAlone(self, home):
        _run(home, SMARTBUDDY_AGENT_ID=None)

        assert "approvals" not in _config(home)


class TestSessionsAndReview:
    """Replies slowed down as one session grew for days (60-140k tokens per
    call, 45 s compressions); the skill review fork replayed it after most
    replies."""

    def test_smartbuddy_pod_NewSessionDailyAt4_NoNotice(self, home):
        _run(home)

        assert _config(home)["session_reset"] == {"mode": "daily", "at_hour": 4, "notify": False}

    def test_smartbuddy_pod_CompressionKeepsLast10(self, home):
        (home / "config.yaml").write_text(yaml.safe_dump({"model": {}, "compression": {"threshold": 0.5}}))

        _run(home)

        assert _config(home)["compression"] == {"threshold": 0.5, "protect_last_n": 10}

    def test_smartbuddy_pod_SkillReviewEvery30Steps_KeepsDisabledSkills(self, home):
        _run(home)

        skills = _config(home)["skills"]
        assert skills["creation_nudge_interval"] == 30
        assert "himalaya" in skills["disabled"]

    def test_non_smartbuddy_pod_LeavesThemAlone(self, home):
        _run(home, SMARTBUDDY_AGENT_ID=None)

        config = _config(home)
        assert "session_reset" not in config
        assert "compression" not in config
        assert "creation_nudge_interval" not in config.get("skills", {})


class TestLongRunningNotice:
    def test_smartbuddy_pod_FirstNoticeAtThreeMinutes(self, home):
        _run(home)

        assert _config(home)["agent"]["gateway_notify_interval"] == 180

    def test_smartbuddy_pod_OldFiveMinuteSetting_LoweredToThree(self, home):
        (home / "config.yaml").write_text(
            yaml.safe_dump({"model": {}, "agent": {"gateway_notify_interval": 300}}))

        _run(home)

        assert _config(home)["agent"]["gateway_notify_interval"] == 180

    def test_smartbuddy_pod_KeepsOtherAgentKeys(self, home):
        (home / "config.yaml").write_text(yaml.safe_dump({"model": {}, "agent": {"max_turns": 90}}))

        _run(home)

        assert _config(home)["agent"]["max_turns"] == 90

    def test_non_smartbuddy_pod_LeavesAgentAlone(self, home):
        _run(home, SMARTBUDDY_AGENT_ID=None)

        assert "agent" not in _config(home)


class TestMailOnlyThroughConnector:
    """himalaya / google-workspace would keep mail passwords inside the pod;
    SmartBuddy reads mail through the console (smartbuddy-mail skill)."""

    def test_smartbuddy_pod_DisablesBundledMailSkills(self, home):
        _run(home)

        assert {"himalaya", "google-workspace"} <= set(_config(home)["skills"]["disabled"])

    def test_smartbuddy_pod_KeepsOtherDisabledSkills_NoDuplicates(self, home):
        (home / "config.yaml").write_text(yaml.safe_dump(
            {"model": {}, "skills": {"disabled": ["yuanbao", "himalaya"]}}))

        _run(home)
        _run(home)

        assert _config(home)["skills"]["disabled"] == ["yuanbao", "himalaya", "google-workspace"]

    def test_smartbuddy_pod_EnablesOutboundConfirm(self, home):
        _run(home)

        assert _config(home)["approvals"]["outbound_confirm"] is True

    def test_non_smartbuddy_pod_LeavesSkillsAlone(self, home):
        _run(home, SMARTBUDDY_AGENT_ID=None)

        assert "skills" not in _config(home)


class TestCronModelSnapshotRealign:
    def test_unpinned_job_with_stale_snapshot_IsRealignedToCurrentModel(self, home):
        _write_jobs(home, [{"id": "a", "name": "Ballet", "model": None, "model_snapshot": "qwen-plus"}])

        _run(home)

        assert _read_jobs(home)[0]["model_snapshot"] == "deepseek-flash"

    def test_pinned_job_IsLeftAlone(self, home):
        _write_jobs(home, [{"id": "a", "model": "qwen-plus", "model_snapshot": "qwen-plus"}])

        _run(home)

        assert _read_jobs(home)[0]["model_snapshot"] == "qwen-plus"

    def test_job_without_snapshot_IsLeftAlone(self, home):
        _write_jobs(home, [{"id": "a", "model": None, "model_snapshot": None}])

        _run(home)

        assert _read_jobs(home)[0]["model_snapshot"] is None

    def test_other_job_fields_ArePreserved(self, home):
        job = {"id": "a", "name": "Ballet", "prompt": "芭蕾", "model": None,
               "model_snapshot": "qwen-plus", "schedule": {"kind": "cron", "expr": "45 16 * * 2"}}
        _write_jobs(home, [job])

        _run(home)

        assert _read_jobs(home)[0] == {**job, "model_snapshot": "deepseek-flash"}

    def test_no_jobs_file_IsNoOp(self, home):
        _run(home)

        assert not (home / "cron" / "jobs.json").exists()

    def test_already_aligned_jobs_file_IsNotRewritten(self, home):
        _write_jobs(home, [{"id": "a", "model": None, "model_snapshot": "deepseek-flash"}])
        before = (home / "cron" / "jobs.json").read_text()

        _run(home)

        assert (home / "cron" / "jobs.json").read_text() == before
