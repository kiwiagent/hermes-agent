"""kiwiagent: the pinned edge-tts must still be accepted by Microsoft.

edge-tts 7.2.7 gets "403 Invalid response status" from the readaloud
websocket (Oct 2026), so every voice reply failed and the app fell back to
the phone's own reader after a 15 s wait. 7.3.1 works.

The live check installs the pinned version into a temp dir and synthesizes
one phrase; it needs network, so it is marked integration:
    pytest -m integration tests/kiwiagent/test_edge_tts_pin.py
"""
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _pinned_spec() -> str:
    # 0.22: the pyproject extra is the single pin (tools.lazy_deps is retired).
    match = re.search(r'^edge-tts = \["(edge-tts==[^"]+)"\]', PYPROJECT.read_text(), re.M)
    assert match, "edge-tts extra not found in pyproject.toml"
    return match.group(1)


def test_edge_tts_pin_IsTheWorkingVersion():
    assert _pinned_spec() == "edge-tts==7.3.1"


def test_edge_tts_BakedIntoTheImage():
    # Runtime installs are off in the image, so the voice replies need it there.
    dockerfile = (PYPROJECT.parent / "Dockerfile").read_text()
    assert "--extra edge-tts" in dockerfile


@pytest.mark.integration
def test_edge_tts_pin_SynthesizesSpeech(tmp_path):
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv not installed")
    target = tmp_path / "pkgs"
    subprocess.run(
        [uv, "pip", "install", "-q", "--python", sys.executable, "--target", str(target), _pinned_spec()],
        check=True,
    )
    script = textwrap.dedent("""
        import asyncio, edge_tts

        async def main():
            size = 0
            async for chunk in edge_tts.Communicate("Hello from SmartBuddy", "en-NZ-MollyNeural").stream():
                if chunk["type"] == "audio":
                    size += len(chunk["data"])
            print(size)

        asyncio.run(main())
    """)
    result = subprocess.run(
        [sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(target)!r})\n{script}"],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr[-500:]
    assert int(result.stdout.strip()) > 1000
