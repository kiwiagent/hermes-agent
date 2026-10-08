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
        # A write to one host may be always-allowed for that host.
        assert prompt["allow_permanent"] is True

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


# ------------------------------------------------------- always-allow rules
#
# Writes to an external service may be always-allowed per host
# (outbound:http:<host>). Email, messages and publishing as the user are a
# HARD rule: always asked, never saved on "always", never honoured from the
# allowlist even when hand-written into config.yaml.

NOTION_CMD = "curl -X POST https://api.notion.com/v1/pages -d '{\"p\": 1}'"
TWO_HOSTS_CMD = "curl https://a.example.com/x | curl -X POST https://b.example.org/y -d @-"
HARD_CASES = {
    "email": ("curl -X POST https://gmail.googleapis.com/gmail/v1/users/me/messages/send -d @m.json",
              "outbound:email"),
    "message": ("curl -X POST https://hooks.slack.com/services/T/B/X -d '{}'", "outbound:message"),
    "publish": ("curl -X POST https://api.x.com/2/tweets -d '{\"text\": \"hi\"}'", "outbound:publish"),
}
HARD_IDS = sorted(HARD_CASES)


@pytest.fixture
def allowlist(monkeypatch):
    perm = set()
    saved = []
    monkeypatch.setattr(A, "_permanent_approved", perm)
    monkeypatch.setattr(A, "save_permanent_allowlist", lambda p: saved.append(set(p)))
    return perm, saved


class TestAlwaysAllowHost:
    def test_single_host_write_offers_always(self, gw_session, allowlist):
        seen = _answer(gw_session, "once")

        A.check_all_command_guards(NOTION_CMD, "local")

        prompt = seen["prompts"][0]
        assert prompt["allow_permanent"] is True
        assert prompt["pattern_key"] == "outbound:http:api.notion.com"

    def test_always_saves_host_and_stops_asking(self, gw_session, allowlist):
        perm, saved = allowlist
        _answer(gw_session, "always")
        A.check_all_command_guards(NOTION_CMD, "local")
        seen = _answer(gw_session, "deny")

        res = A.check_all_command_guards(NOTION_CMD, "local")

        assert perm == {"outbound:http:api.notion.com"}
        assert saved and "outbound:http:api.notion.com" in saved[-1]
        assert res["approved"] is True
        assert "prompts" not in seen

    def test_allowed_host_does_not_cover_other_host(self, gw_session, allowlist):
        allowlist[0].add("outbound:http:api.notion.com")
        seen = _answer(gw_session, "deny")

        res = A.check_all_command_guards(POST_CMD, "local")

        assert res["approved"] is False
        assert len(seen["prompts"]) == 1

    def test_several_hosts_never_offer_always(self, gw_session, allowlist):
        perm, saved = allowlist
        seen = _answer(gw_session, "always")

        A.check_all_command_guards(TWO_HOSTS_CMD, "local")

        assert seen["prompts"][0]["allow_permanent"] is False
        assert perm == set() and saved == []

    def test_execute_code_always_saves_host_only(self, gw_session, allowlist):
        perm, _ = allowlist
        code = "import requests\nrequests.post('https://api.notion.com/v1/pages', json=p)\n"
        seen = _answer(gw_session, "always")

        A.check_execute_code_guard(code, "local")

        assert seen["prompts"][0]["allow_permanent"] is True
        assert perm == {"outbound:http:api.notion.com"}

    def test_cli_always_saves_host(self, gw_session, allowlist, monkeypatch):
        perm, _ = allowlist
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        offered = []

        def cb(command, description, *, allow_permanent=True, smart_denied=False):
            offered.append(allow_permanent)
            return "always"

        A.check_all_command_guards(NOTION_CMD, "local", approval_callback=cb)

        assert offered == [True]
        assert perm == {"outbound:http:api.notion.com"}


@pytest.mark.parametrize("kind", HARD_IDS)
class TestHardRule:
    def test_never_offers_always(self, gw_session, allowlist, kind):
        command, key = HARD_CASES[kind]
        seen = _answer(gw_session, "once")

        A.check_all_command_guards(command, "local")

        assert seen["prompts"][0]["pattern_key"] == key
        assert seen["prompts"][0]["allow_permanent"] is False

    def test_approve_always_is_not_saved(self, gw_session, allowlist, kind):
        perm, saved = allowlist
        command, _ = HARD_CASES[kind]
        _answer(gw_session, "always")

        res = A.check_all_command_guards(command, "local")
        seen = _answer(gw_session, "deny")
        again = A.check_all_command_guards(command, "local")

        assert res["approved"] is True, "approved for this one action only"
        assert perm == set() and saved == []
        assert again["approved"] is False and len(seen["prompts"]) == 1

    def test_hand_written_allowlist_is_ignored(self, gw_session, allowlist, kind):
        command, key = HARD_CASES[kind]
        allowlist[0].update({key, command, "*", "curl *",
                             "outbound:http:api.x.com", "outbound:http:hooks.slack.com",
                             "outbound:http:gmail.googleapis.com"})
        seen = _answer(gw_session, "deny")

        res = A.check_all_command_guards(command, "local")

        assert res["approved"] is False
        assert len(seen["prompts"]) == 1

    def test_cli_never_offers_or_saves_always(self, gw_session, allowlist, monkeypatch, kind):
        perm, saved = allowlist
        command, _ = HARD_CASES[kind]
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        offered = []

        def cb(command, description, *, allow_permanent=True, smart_denied=False):
            offered.append(allow_permanent)
            return "always"

        A.check_all_command_guards(command, "local", approval_callback=cb)

        assert offered == [False]
        assert perm == set() and saved == []

    def test_cron_still_drafts_even_if_hand_allowed(self, gw_session, allowlist, monkeypatch, kind):
        command, key = HARD_CASES[kind]
        allowlist[0].update({key, command, "outbound:http:api.x.com",
                             "outbound:http:hooks.slack.com", "outbound:http:gmail.googleapis.com"})
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
        monkeypatch.setattr(A, "_get_cron_approval_mode", lambda: "approve")

        res = A.check_all_command_guards(command, "local")

        assert res["approved"] is False
        assert "draft" in res["message"].lower()


class TestHardRuleExecuteCode:
    def test_email_code_always_is_not_saved(self, gw_session, allowlist):
        perm, saved = allowlist
        _answer(gw_session, "always")

        A.check_execute_code_guard(EMAIL_CODE, "local")

        assert perm == set() and saved == []

    def test_email_code_ignores_hand_written_allowlist(self, gw_session, allowlist):
        allowlist[0].update({"outbound:email", "execute_code"})
        seen = _answer(gw_session, "deny")

        assert A.check_execute_code_guard(EMAIL_CODE, "local")["approved"] is False
        assert len(seen["prompts"]) == 1


class TestCronAllowedHost:
    @pytest.fixture
    def cron(self, gw_session, monkeypatch):
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
        monkeypatch.setattr(A, "_get_cron_approval_mode", lambda: "deny")

    def test_allowed_host_write_runs(self, cron, allowlist):
        allowlist[0].add("outbound:http:api.notion.com")

        assert A.check_all_command_guards(NOTION_CMD, "local")["approved"] is True

    def test_not_allowed_host_still_drafts(self, cron, allowlist):
        allowlist[0].add("outbound:http:api.notion.com")

        res = A.check_all_command_guards(POST_CMD, "local")

        assert res["approved"] is False
        assert "draft" in res["message"].lower()


# ---------------------------------------- always-allow needs literal targets

NOTION_ALLOWED = "outbound:http:api.notion.com"
LITERAL_CASES = {
    "comment_then_variable": ("# https://api.notion.com/v1/pages\nimport requests\nrequests.post(url, json=p)\n", False),
    "literal_plus_variable": ("import requests\nrequests.post('https://api.notion.com/v1/pages', json=p)\n"
                              "requests.post(url, json=p)\n", False),
    "two_literal_notion": ("import requests\nrequests.post('https://api.notion.com/v1/pages', json=p)\n"
                           "requests.patch('https://api.notion.com/v1/pages/1', json=q)\n", True),
    "fstring_literal_host": ('import requests\nrequests.post(f"https://api.notion.com/v1/pages/{pid}", json=p)\n', True),
}
LITERAL_IDS = sorted(LITERAL_CASES)


def _as_command(tmp_path, monkeypatch, code):
    (tmp_path / "job.py").write_text(code)
    monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
    return "python3 job.py"


@pytest.mark.parametrize("case", LITERAL_IDS)
class TestAllowedHostNeedsLiteralTargets:
    def test_terminal(self, gw_session, allowlist, tmp_path, monkeypatch, case):
        code, auto = LITERAL_CASES[case]
        allowlist[0].add(NOTION_ALLOWED)
        seen = _answer(gw_session, "deny")

        res = A.check_all_command_guards(_as_command(tmp_path, monkeypatch, code), "local")

        assert res["approved"] is auto
        assert ("prompts" not in seen) is auto
        if not auto:
            assert seen["prompts"][0]["allow_permanent"] is False

    def test_execute_code(self, gw_session, allowlist, monkeypatch, case):
        code, auto = LITERAL_CASES[case]
        allowlist[0].add(NOTION_ALLOWED)
        # isolate the outbound decision from the generic execute_code prompt
        monkeypatch.setattr(A, "_smart_approve", lambda c, d: "approve")
        seen = _answer(gw_session, "deny")

        res = A.check_execute_code_guard(code, "local")

        assert res["approved"] is auto
        if not auto:
            assert seen["prompts"][0]["allow_permanent"] is False

    def test_offer_always_only_for_literal(self, gw_session, allowlist, tmp_path, monkeypatch, case):
        code, auto = LITERAL_CASES[case]
        seen = _answer(gw_session, "once")

        A.check_all_command_guards(_as_command(tmp_path, monkeypatch, code), "local")

        assert seen["prompts"][0]["allow_permanent"] is auto

    def test_cron(self, gw_session, allowlist, tmp_path, monkeypatch, case):
        code, auto = LITERAL_CASES[case]
        allowlist[0].add(NOTION_ALLOWED)
        command = _as_command(tmp_path, monkeypatch, code)
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
        monkeypatch.setattr(A, "_get_cron_approval_mode", lambda: "deny")

        res = A.check_all_command_guards(command, "local")

        assert res["approved"] is auto
        if not auto:
            assert "draft" in res["message"].lower()


# ------------------------------------------------ permanent approvals list

class TestListPermanentApprovals:
    def test_lists_http_hosts_then_commands_never_hard_keys(self, allowlist):
        allowlist[0].update({
            "recursive delete", "outbound:http:api.notion.com", "podman *",
            "outbound:http:hooks.zapier.com",
            # hand-written, hard-blocked or meaningless: never listed
            "outbound:email", "outbound:message", "outbound:publish",
            "outbound:http", "outbound:http:api.x.com", "outbound:email:x",
        })

        assert A.list_permanent_approvals() == [
            {"key": "outbound:http:api.notion.com", "kind": "http", "target": "api.notion.com"},
            {"key": "outbound:http:hooks.zapier.com", "kind": "http", "target": "hooks.zapier.com"},
            {"key": "podman *", "kind": "command", "target": "podman *"},
            {"key": "recursive delete", "kind": "command", "target": "recursive delete"},
        ]

    def test_empty(self, allowlist):
        assert A.list_permanent_approvals() == []


class TestRevokePermanent:
    def test_removes_from_memory_and_config(self, allowlist):
        perm, saved = allowlist
        perm.update({"outbound:http:api.notion.com", "recursive delete"})

        assert A.revoke_permanent("outbound:http:api.notion.com") is True

        assert perm == {"recursive delete"}
        assert saved == [{"recursive delete"}]

    def test_unknown_key_changes_nothing(self, allowlist):
        perm, saved = allowlist
        perm.add("recursive delete")

        assert A.revoke_permanent("outbound:http:api.notion.com") is False

        assert perm == {"recursive delete"} and saved == []

    def test_revoked_host_asks_again(self, gw_session, allowlist):
        allowlist[0].add("outbound:http:api.notion.com")
        A.revoke_permanent("outbound:http:api.notion.com")
        seen = _answer(gw_session, "deny")

        assert A.check_all_command_guards(NOTION_CMD, "local")["approved"] is False
        assert len(seen["prompts"]) == 1


# ------------------------------------ exemptions need literal write targets

class TestExemptionsNeedLiteralTargets:
    @pytest.mark.parametrize("code", [
        "# http://localhost:8642/v1\nimport requests\nrequests.post(url, json=b)\n",
        "# https://api.notion.com/v1/search\nimport requests\nrequests.post(url, json={})\n",
        "await fetch(process.env.HOOK, {method: 'POST', body})\n// http://localhost:3000\n",
    ])
    def test_gateway_asks(self, gw_session, code):
        seen = _answer(gw_session, "deny")

        res = A.check_execute_code_guard(code, "local")

        assert res["approved"] is False
        assert len(seen["prompts"]) == 1

    @pytest.mark.parametrize("name,code", [
        ("job.py", "# http://localhost:8642/v1\nimport requests\nrequests.post(url, json=b)\n"),
        ("job.mjs", "await fetch(process.env.HOOK, {method: 'POST', body})\n"),
    ])
    def test_cron_drafts(self, gw_session, tmp_path, monkeypatch, name, code):
        (tmp_path / name).write_text(code)
        monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
        monkeypatch.setattr(A, "_get_cron_approval_mode", lambda: "approve")

        res = A.check_all_command_guards(f"node {name}" if name.endswith(".mjs") else f"python3 {name}", "local")

        assert res["approved"] is False
        assert "draft" in res["message"].lower()


# ------------------------------------ host key through a base URL constant

NOTION_BASE_CODE = ('import requests\nAPI_URL = "https://api.notion.com/v1"\n'
                    'requests.post(f"{API_URL}/pages", json=page)\n')
NOTION_BASE_SHADOWED = ('import requests\nAPI_URL = "https://api.notion.com/v1"\n'
                        'def create(API_URL, page):\n'
                        '    requests.post(f"{API_URL}/pages", json=page)\n')


class TestHostKeyThroughBaseConstant:
    def test_offers_always_and_saves_host(self, gw_session, allowlist, tmp_path, monkeypatch):
        perm, _ = allowlist
        seen = _answer(gw_session, "always")

        A.check_all_command_guards(_as_command(tmp_path, monkeypatch, NOTION_BASE_CODE), "local")

        assert seen["prompts"][0]["allow_permanent"] is True
        assert perm == {NOTION_ALLOWED}

    def test_auto_allowed_once_allowed(self, gw_session, allowlist, tmp_path, monkeypatch):
        allowlist[0].add(NOTION_ALLOWED)
        seen = _answer(gw_session, "deny")

        res = A.check_all_command_guards(_as_command(tmp_path, monkeypatch, NOTION_BASE_CODE), "local")

        assert res["approved"] is True and "prompts" not in seen

    def test_cron_runs_once_allowed(self, gw_session, allowlist, tmp_path, monkeypatch):
        allowlist[0].add(NOTION_ALLOWED)
        command = _as_command(tmp_path, monkeypatch, NOTION_BASE_CODE)
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
        monkeypatch.setattr(A, "_get_cron_approval_mode", lambda: "deny")

        assert A.check_all_command_guards(command, "local")["approved"] is True

    def test_shadowed_base_asks_without_always(self, gw_session, allowlist, tmp_path, monkeypatch):
        allowlist[0].add(NOTION_ALLOWED)
        seen = _answer(gw_session, "deny")

        res = A.check_all_command_guards(_as_command(tmp_path, monkeypatch, NOTION_BASE_SHADOWED), "local")

        assert res["approved"] is False
        assert seen["prompts"][0]["allow_permanent"] is False
