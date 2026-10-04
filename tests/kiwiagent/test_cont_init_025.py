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
