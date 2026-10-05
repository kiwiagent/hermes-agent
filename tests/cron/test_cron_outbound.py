"""kiwiagent: cron jobs never send anything out in the user's name.

A job's own script (no_agent / data-collection) runs without an agent turn,
so the terminal / execute_code guards never see it. With
approvals.outbound_confirm on, a script that would send (email, messages,
external writes) is not run, and the user gets a plain-language notice.
"""
import pytest

import cron.scheduler as s
from tools import approval as A


@pytest.fixture
def scripts_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(s, "_get_hermes_home", lambda: tmp_path)
    d = tmp_path / "scripts"
    d.mkdir()
    return d


def test_outbound_script_not_run(scripts_dir, monkeypatch):
    monkeypatch.setattr(A, "_outbound_confirm_enabled", lambda: True)
    marker = scripts_dir / "ran.txt"
    (scripts_dir / "weekly_report.py").write_text(
        "import smtplib\n"
        f"open({str(marker)!r}, 'w').write('sent')\n"
    )

    ok, out = s._run_job_script("weekly_report.py")

    assert ok is False
    assert out.startswith("Outbound blocked:")
    assert not marker.exists(), "the script must not run"


def test_read_only_script_runs(scripts_dir, monkeypatch):
    monkeypatch.setattr(A, "_outbound_confirm_enabled", lambda: True)
    (scripts_dir / "check.py").write_text("print('3 new emails')\n")

    ok, out = s._run_job_script("check.py")

    assert ok is True and "3 new emails" in out


def test_flag_off_runs_as_before(scripts_dir, monkeypatch):
    monkeypatch.setattr(A, "_outbound_confirm_enabled", lambda: False)
    (scripts_dir / "send.py").write_text("import smtplib\nprint('done')\n")

    ok, out = s._run_job_script("send.py")

    assert ok is True and "done" in out


def _job(name, kind="cron"):
    schedule = {"kind": kind, "expr": "0 9 * * 1"} if kind == "cron" else {"kind": "once"}
    return {"id": "j1", "name": name, "prompt": name, "schedule": schedule, "failure_streak": 0}


def test_friendly_notice_english():
    msg = s._friendly_cron_failure_message(
        _job("Weekly report to boss"),
        "Outbound blocked: this script would send an email on the user's behalf.")

    assert "needs your OK" in msg
    assert "Weekly report to boss" in msg
    assert "smtplib" not in msg and "Outbound blocked" not in msg


def test_friendly_notice_chinese():
    msg = s._friendly_cron_failure_message(
        _job("每周给老板发周报"),
        "Outbound blocked: this script would send an email on the user's behalf.")

    assert "每周给老板发周报" in msg
    assert "确认" in msg
