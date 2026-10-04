"""kiwiagent image: agents may write under /opt/data and /tmp.

Buddies routinely write scratch scripts to /tmp; with only /opt/data allowed
those writes were denied and users got a "File-mutation verifier" footer.
The value is read from the Dockerfile and checked with hermes' own guard.
"""
import re
from pathlib import Path

import pytest

from agent.file_safety import is_write_denied

DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile"


@pytest.fixture()
def image_safe_root(monkeypatch):
    match = re.search(r"^ENV HERMES_WRITE_SAFE_ROOT=(\S+)$", DOCKERFILE.read_text(), re.M)
    assert match, "HERMES_WRITE_SAFE_ROOT not set in Dockerfile"
    monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", match.group(1))
    return match.group(1)


@pytest.mark.parametrize("path", ["/opt/data/notes/todo.md", "/tmp/notion_bug_push.py"])
def test_image_safe_root_AllowsDataAndTmp(image_safe_root, path):
    assert not is_write_denied(path)


@pytest.mark.parametrize("path", ["/etc/hosts", "/opt/hermes/run_agent.py", "/usr/local/bin/x"])
def test_image_safe_root_StillDeniesSystemPaths(image_safe_root, path):
    assert is_write_denied(path)
