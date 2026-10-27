"""Stop private browser executions at a bot wall and release their browser."""

import logging
import subprocess

logger = logging.getLogger(__name__)
CHALLENGE_MARKER = "HERMES_BROWSER_BOT_CHALLENGE"

# Runs inside the harness, where navigation helpers and js() are pre-imported.
# Check before model-authored waits, rather than inspecting stdout after a long retry loop.
CHALLENGE_GUARD = '''
_hermes_probe_js = js
def _hermes_check_challenge():
    try:
        page = _hermes_probe_js("({title: document.title, text: (document.body?.innerText || '').slice(0, 2000)})")
    except Exception:
        return
    if not isinstance(page, dict):
        return
    title = str(page.get('title', '')).strip().lower()
    text = str(page.get('text', '')).lower()
    challenge_title = title in ('just a moment...', 'just a moment', 'attention required! | cloudflare', 'security verification')
    challenge_body = any(s in text for s in ('performing security verification', 'verify you are human', 'checking your browser', 'enable javascript and cookies to continue'))
    if challenge_title and challenge_body:
        raise RuntimeError('HERMES_BROWSER_BOT_CHALLENGE: bot verification requires a different source; do not wait or retry this page.')
def _hermes_guard_browser_call(fn):
    def guarded(*args, **kwargs):
        result = fn(*args, **kwargs)
        _hermes_check_challenge()
        return result
    return guarded
for _hermes_name in ('new_tab', 'goto_url', 'wait_for_load', 'js', 'page_info'):
    if callable(globals().get(_hermes_name)):
        globals()[_hermes_name] = _hermes_guard_browser_call(globals()[_hermes_name])
_hermes_check_challenge()
'''


def release_challenged_browser(cmd, env, task_id, session, sidecar, *, fenced=False):
    """Close only this private route; never close a human-controlled shared screen."""
    from tools import browser_use_cli as bu
    from tools.browser_tool_lifecycle import _human_holds_shared_browser
    from tools.browser_tool_session import run_fenced

    key = bu._backend_cache_key(task_id, session, sidecar)

    def release():
        if _human_holds_shared_browser(key):
            return {"browser_released": False}
        try:
            bu._run_cli_killing_process_group([*cmd, "--reload"], "", env, 15)
        except (OSError, subprocess.SubprocessError):
            logger.warning("Could not stop challenged browser harness", exc_info=True)
        return {"browser_released": _close_private_route(key, env, fenced=fenced)}

    result = run_fenced({"features": {"local": True}}, release) if fenced else release()
    return {"browser_released": False, **result}


def _close_private_route(key, env, *, fenced):
    from tools import browser_use_cli as bu
    from tools.browser_tool_lifecycle import cleanup_browser_session, _human_holds_shared_browser
    from tools.bot_desktop import lease

    def close():
        # Revalidate after the possibly slow harness reload.
        if _human_holds_shared_browser(key):
            return False
        cleanup_browser_session(key)
        with bu._driven_daemons_lock:
            bu._driven_daemons.discard(env.get("BU_NAME", "default"))
        return True

    if not fenced:
        return close()
    if lease.fcntl is None:
        return False  # Without cross-process exclusion, leave a human-capable browser to its janitor.
    # A post-action epoch check cannot undo a browser kill. Serialize destructive
    # teardown with the EXISTING human-control transition lock instead.
    with lease._locked(lease._path(None)):
        return False if lease.human_holds() else close()
