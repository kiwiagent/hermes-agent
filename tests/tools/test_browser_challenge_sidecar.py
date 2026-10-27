"""Bot-wall cleanup must not expand to the route's hybrid sibling."""
import subprocess

from tools import browser_tool as bt
from tools import browser_tool_lifecycle as lifecycle
from tools import browser_use_cli as bu
from tools.browser_use_challenge import release_challenged_browser


def test_cloud_challenge_preserves_human_sidecar_and_its_binding(monkeypatch):
    primary = bu._backend_cache_key('research', 'research')
    sidecar = primary + '::local'
    closed = []
    monkeypatch.setattr(bt, '_active_sessions', {primary: {}, sidecar: {'features': {'local': True}}})
    monkeypatch.setattr(bt, '_last_active_session_key', {primary: sidecar})
    monkeypatch.setattr(lifecycle, '_human_holds_shared_browser', lambda key: key == sidecar)
    monkeypatch.setattr(lifecycle, '_cleanup_single_browser_session', closed.append)
    monkeypatch.setattr(bu, '_run_cli_killing_process_group', lambda *args: subprocess.CompletedProcess(args[0], 0, '', ''))
    result = release_challenged_browser(['fake-browser'], {}, 'research', 'research', False)
    assert result['browser_released'] is True
    assert closed == [primary]
    assert bt._last_active_session_key[primary] == sidecar
