"""kiwiagent: approvals.outbound_confirm — "Every action needs your approval".

With the flag on, anything sent out in the user's name (email, messages to
others, writes to external services) always asks the user — smart approval
can't wave it through and "approve for session/always" doesn't carry over.
Cron jobs never send: the agent is told to put a draft in its reply instead.
With the flag off nothing changes.
"""
import pytest

from tools import approval as A

EMAIL_CODE = "import smtplib\nwith smtplib.SMTP_SSL('smtp.gmail.com') as s:\n    s.send_message(m)\n"
POST_CMD = "curl -X POST https://api.example.com/orders -d '{\"qty\": 1}'"


@pytest.fixture
def gw_session(monkeypatch):
    monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    monkeypatch.delenv("HERMES_CRON_SESSION", raising=False)
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)
    monkeypatch.setattr(A, "_YOLO_MODE_FROZEN", False)
    # SmartBuddy runs smart mode; the aux model would happily approve these.
    monkeypatch.setattr(A, "_get_approval_mode", lambda: "smart")
    monkeypatch.setattr(A, "_smart_approve", lambda c, d: "approve")
    monkeypatch.setattr(A, "_outbound_confirm_enabled", lambda: True)
    session_key = "outbound-test-session"
    token = A.set_current_session_key(session_key)
    with A._lock:
        A._gateway_queues.pop(session_key, None)
        A._gateway_notify_cbs.pop(session_key, None)
    A._session_approved.pop(session_key, None) if hasattr(A, "_session_approved") else None
    try:
        yield session_key
    finally:
        A.reset_current_session_key(token)
        with A._lock:
            A._gateway_queues.pop(session_key, None)
            A._gateway_notify_cbs.pop(session_key, None)


def _answer(session_key, choice):
    seen = {}

    def cb(approval_data):
        seen.setdefault("prompts", []).append(approval_data)
        with A._lock:
            entries = A._gateway_queues.get(session_key, [])
            if entries:
                entries[-1].result = choice
                entries[-1].event.set()

    with A._lock:
        A._gateway_notify_cbs[session_key] = cb
    return seen


# ---------------------------------------------------------------- terminal

class TestTerminal:
    def test_flag_off_unchanged(self, gw_session, monkeypatch):
        monkeypatch.setattr(A, "_outbound_confirm_enabled", lambda: False)
        seen = _answer(gw_session, "deny")

        assert A.check_all_command_guards(POST_CMD, "local")["approved"] is True
        assert "prompts" not in seen

    def test_outbound_always_asks_user_even_in_smart_mode(self, gw_session):
        seen = _answer(gw_session, "once")

        res = A.check_all_command_guards(POST_CMD, "local")

        assert res["approved"] is True
        prompt = seen["prompts"][0]
        assert "send data to api.example.com" in prompt["description"]
        assert prompt["allow_permanent"] is False

    def test_user_denies_blocks(self, gw_session):
        _answer(gw_session, "deny")

        res = A.check_all_command_guards(POST_CMD, "local")

        assert res["approved"] is False
        assert "BLOCKED" in res["message"]

    def test_session_approval_does_not_carry_over(self, gw_session):
        _answer(gw_session, "session")
        A.check_all_command_guards(POST_CMD, "local")
        seen = _answer(gw_session, "once")

        A.check_all_command_guards(POST_CMD, "local")

        assert len(seen["prompts"]) == 1, "every send must be asked again"

    def test_script_file_is_scanned(self, gw_session, tmp_path, monkeypatch):
        (tmp_path / "send_report.py").write_text(EMAIL_CODE)
        monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
        seen = _answer(gw_session, "once")

        A.check_all_command_guards("python3 send_report.py", "local")

        assert seen["prompts"][0]["description"] == "send an email"

    def test_harmless_command_not_asked(self, gw_session):
        seen = _answer(gw_session, "deny")

        assert A.check_all_command_guards("curl https://api.example.com/x", "local")["approved"] is True
        assert "prompts" not in seen

    def test_cron_never_sends_and_asks_for_a_draft(self, gw_session, monkeypatch):
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
        monkeypatch.setattr(A, "_get_cron_approval_mode", lambda: "approve")

        res = A.check_all_command_guards(POST_CMD, "local")

        assert res["approved"] is False
        assert "draft" in res["message"].lower()

    def test_no_approval_surface_blocks(self, gw_session, monkeypatch):
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)

        assert A.check_all_command_guards(POST_CMD, "local")["approved"] is False


# ------------------------------------------------------------ execute_code

class TestExecuteCode:
    def test_flag_off_unchanged(self, gw_session, monkeypatch):
        monkeypatch.setattr(A, "_outbound_confirm_enabled", lambda: False)

        res = A.check_execute_code_guard(EMAIL_CODE, "local")

        assert res["approved"] is True and res.get("smart_approved") is True

    def test_outbound_code_always_asks_user(self, gw_session):
        seen = _answer(gw_session, "once")

        res = A.check_execute_code_guard(EMAIL_CODE, "local")

        assert res["approved"] is True
        prompt = seen["prompts"][0]
        assert "send an email" in prompt["description"]
        assert prompt["allow_permanent"] is False

    def test_earlier_session_approval_does_not_cover_sending(self, gw_session):
        A.approve_session(gw_session, "execute_code")
        seen = _answer(gw_session, "deny")

        res = A.check_execute_code_guard(EMAIL_CODE, "local")

        assert res["approved"] is False
        assert len(seen["prompts"]) == 1

    def test_harmless_code_keeps_smart_mode(self, gw_session):
        res = A.check_execute_code_guard("print(1 + 1)", "local")

        assert res["approved"] is True and res.get("smart_approved") is True

    def test_cron_never_sends_even_when_cron_mode_approve(self, gw_session, monkeypatch):
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
        monkeypatch.setattr(A, "_get_cron_approval_mode", lambda: "approve")

        res = A.check_execute_code_guard(EMAIL_CODE, "local")

        assert res["approved"] is False
        assert "draft" in res["message"].lower()
