"""A bot challenge must stop browser work and release only its owned browser."""
import contextlib
import io
import json
import subprocess
from unittest.mock import Mock

import pytest

from tools import browser_use_cli as bu
from tools import browser_tool_lifecycle as lifecycle


@pytest.fixture
def owned_browser(monkeypatch):
    monkeypatch.setattr(bu, '_find_cli', lambda: ['fake-browser'])
    monkeypatch.setattr(bu, '_base_subprocess_env', dict)
    monkeypatch.setattr(bu, '_code_url_verdict', lambda code: bu._CodeUrlVerdict(None, False))
    monkeypatch.setattr(bu, '_read_browser_cfg', dict)
    monkeypatch.setattr(bu, '_workspace_dir', lambda task_id: None)
    monkeypatch.setattr(bu, '_attach_vault_supervisor', lambda *args: None)
    monkeypatch.setattr(bu, '_find_screenshot', lambda *args: None)
    monkeypatch.setattr(lifecycle, '_human_holds_shared_browser', lambda key: False)
    def route(env, *args, **kwargs):
        env[bu._PRIVATE_BROWSER_SENTINEL] = '1'
    monkeypatch.setattr(bu, '_route_backend', route)
    cleaned = Mock()
    monkeypatch.setattr(lifecycle, 'cleanup_browser_session', cleaned)
    return cleaned


def test_challenge_stops_before_waiting_and_frees_owned_browser(monkeypatch, owned_browser):
    waited = []
    def run(cmd, code, env, timeout):
        if '--reload' in cmd:
            return subprocess.CompletedProcess(cmd, 0, '', '')
        def js(expr):
            return {'title': 'Just a moment...', 'text': 'Performing security verification. Verify you are human.'}
        namespace = {'new_tab': lambda url: None, 'wait_for_load': lambda: None,
                     'js': js, 'expensive_retry': lambda: waited.append(True)}
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                exec(code, namespace)
        except Exception as exc:
            stderr.write(str(exc))
        return subprocess.CompletedProcess(cmd, bool(stderr.getvalue()), stdout.getvalue(), stderr.getvalue())
    monkeypatch.setattr(bu, '_run_cli_killing_process_group', run)
    result = json.loads(bu.browser_exec('new_tab("https://example.com/offers")\nwait_for_load()\nexpensive_retry()', task_id='research'))
    assert waited == []
    assert result['success'] is False
    assert result['error_type'] == 'bot_challenge'
    owned_browser.assert_called_once_with(bu._backend_cache_key('research'))


def test_plain_page_containing_cloudflare_does_not_close_browser(monkeypatch, owned_browser):
    monkeypatch.setattr(bu, '_run_cli_killing_process_group', lambda *args: subprocess.CompletedProcess(args[0], 0, 'Article: How Cloudflare works', ''))
    result = json.loads(bu.browser_exec('print("Article: How Cloudflare works")', task_id='research'))
    assert result['success'] is True
    owned_browser.assert_not_called()


def test_shared_browser_is_not_guarded_or_closed(monkeypatch, owned_browser):
    monkeypatch.setattr(bu, '_route_backend', lambda *args, **kwargs: None)
    payloads = []
    def run(cmd, code, env, timeout):
        payloads.append(code)
        return subprocess.CompletedProcess(cmd, 0, 'Shared browser awaiting human verification', '')
    monkeypatch.setattr(bu, '_run_cli_killing_process_group', run)
    original = 'wait_for_load()'
    result = json.loads(bu.browser_exec(original, task_id='shared'))
    assert result['success']
    assert payloads == [original]
    owned_browser.assert_not_called()


def test_human_control_prevents_challenge_cleanup(monkeypatch, owned_browser):
    monkeypatch.setattr(lifecycle, '_human_holds_shared_browser', lambda key: True)
    monkeypatch.setattr(bu, '_run_cli_killing_process_group', lambda *args: subprocess.CompletedProcess(args[0], 1, '', 'HERMES_BROWSER_BOT_CHALLENGE'))
    result = json.loads(bu.browser_exec('wait_for_load()', task_id='research'))
    assert result['error_type'] == 'bot_challenge'
    assert result['browser_released'] is False
    owned_browser.assert_not_called()


def test_human_takeover_during_reload_prevents_teardown(monkeypatch, owned_browser):
    human = [False]
    monkeypatch.setattr(lifecycle, '_human_holds_shared_browser', lambda key: human[0])
    def run(cmd, code, env, timeout):
        if '--reload' in cmd:
            human[0] = True
            return subprocess.CompletedProcess(cmd, 0, '', '')
        return subprocess.CompletedProcess(cmd, 1, '', 'HERMES_BROWSER_BOT_CHALLENGE')
    monkeypatch.setattr(bu, '_run_cli_killing_process_group', run)
    result = json.loads(bu.browser_exec('wait_for_load()', task_id='research'))
    assert result['browser_released'] is False
    owned_browser.assert_not_called()


@pytest.mark.platforms('posix')
def test_destructive_close_excludes_human_ownership_transition(monkeypatch, owned_browser):
    import fcntl
    from tools.bot_desktop import lease
    from tools.browser_use_challenge import release_challenged_browser
    blocked = []
    def cleanup(key):
        with lease._path(None).with_suffix('.lock').open('a+') as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                blocked.append(True)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    monkeypatch.setattr(lifecycle, 'cleanup_browser_session', cleanup)
    monkeypatch.setattr(bu, '_run_cli_killing_process_group', lambda *args: subprocess.CompletedProcess(args[0], 0, '', ''))
    result = release_challenged_browser(['fake-browser'], {}, 'research', '', False, fenced=True)
    assert result['browser_released'] is True
    assert blocked == [True]
