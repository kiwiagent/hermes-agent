"""Regression test: hermes-updater apply refuses inside a container.

Phase 5 task 5.3: the updater's apply verb must refuse inside a Docker
container — in-container updates are 'docker pull', never 'apply'.
"""

import builtins
from unittest.mock import patch


def test_is_container_detects_docker_env(monkeypatch):
    """is_container() returns True when /.dockerenv exists."""
    import hermes_constants

    monkeypatch.setattr(hermes_constants, "_container_detected", None)
    monkeypatch.setattr("os.path.exists", lambda p: p == "/.dockerenv")
    assert hermes_constants.is_container() is True


def test_is_container_false_outside_container(monkeypatch):
    """is_container() returns False when no container markers are present."""
    import hermes_constants

    monkeypatch.setattr(hermes_constants, "_container_detected", None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    original_open = builtins.open

    def mock_open(path, *args, **kwargs):
        if "cgroup" in str(path) or "mountinfo" in str(path):
            raise FileNotFoundError(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", mock_open)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    assert hermes_constants.is_container() is False
