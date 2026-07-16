"""Docker image contract for the managed release-bundle layout."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_dockerfile_requires_bundle_context_and_installs_one_managed_slot() -> None:
    text = (ROOT / "Dockerfile").read_text()
    assert "FROM hermes_bundle AS bundle" in text
    assert "COPY --from=bundle / /opt/hermes/versions/docker/" in text
    assert "printf 'docker\\n' > /opt/hermes/current.txt" in text
    assert "COPY . ." not in text
    assert "uv sync" not in text
    assert "npm install" not in text
    assert "npm run build" not in text


def test_dockerfile_preserves_native_launchers_and_uses_external_exec_shim() -> None:
    text = (ROOT / "Dockerfile").read_text()
    assert "cp /opt/hermes/versions/docker/bin/hermes /opt/hermes/bin/hermes" in text
    assert "cp /opt/hermes/versions/docker/bin/hermes-updater /opt/hermes/bin/hermes-updater" in text
    assert "COPY --chmod=0755 docker/hermes-exec-shim.sh /usr/local/bin/hermes" in text
    assert "cp /opt/hermes/docker/hermes-exec-shim.sh /opt/hermes/bin/hermes" not in text


def test_container_scripts_resolve_the_active_slot() -> None:
    forbidden = "/opt/hermes/.venv"
    scripts = [
        ROOT / "docker/main-wrapper.sh",
        ROOT / "docker/stage2-hook.sh",
        ROOT / "docker/cont-init.d/02-reconcile-profiles",
        ROOT / "docker/s6-rc.d/dashboard/run",
        ROOT / "docker/hermes-exec-shim.sh",
    ]
    for script in scripts:
        text = script.read_text()
        assert forbidden not in text, f"legacy checkout venv path remains in {script}"

    helper = (ROOT / "docker/slot-env.sh").read_text()
    assert 'current.txt' in helper
    assert 'versions/$HERMES_SLOT_VERSION' in helper
    assert 'runtime/venv' in helper
    assert 'bin/python' in helper


def test_runtime_paths_follow_bundle_layout_and_lazy_target_stays_durable() -> None:
    text = (ROOT / "Dockerfile").read_text()
    assert "ENV HERMES_WEB_DIST=/opt/hermes/versions/docker/ui/web/dist" in text
    assert "ENV HERMES_TUI_DIR=/opt/hermes/versions/docker/ui/tui" in text
    assert "ENV HERMES_LAZY_INSTALL_TARGET=/opt/data/lazy-packages" in text
    assert "ENV HERMES_DISABLE_LAZY_INSTALLS=1" in text
    assert "ENV PLAYWRIGHT_BROWSERS_PATH=/opt/data/ms-playwright" in text
    assert 'ENTRYPOINT [ "/init", "/opt/docker/main-wrapper.sh" ]' in text
