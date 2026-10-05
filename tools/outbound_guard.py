"""kiwiagent: detect actions that go out in the user's name.

SmartBuddy promises "Every action needs your approval". Reading things is
fine; sending an email, messaging someone or writing data to an external
service is not something the buddy may do on its own. This module only
detects such actions in a shell command, a script file the command runs, or
an execute_code script. ``tools.approval`` decides what to do with them
(always ask the user; never run from cron) when ``approvals.outbound_confirm``
is on.

Detection is pattern-based and best effort: it catches the ways the agent
normally sends things (smtplib, Gmail API, curl/wget/httpie writes,
requests/httpx writes, chat webhooks). It is a guard rail, not a sandbox.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, Tuple

_FLAGS = re.IGNORECASE | re.MULTILINE

_EMAIL_PATTERNS = [
    r"\bsmtplib\b",
    r"\bSMTP(?:_SSL)?\s*\(",
    r"\bsendmail\b",
    r"\bmsmtp\b",
    r"\bswaks\b",
    r"(?:^|[\s;|&(])mail\s+-s\b",
    r"\bmutt\b\s",
    r"\b(?:messages|drafts)\(\)\s*\.\s*send\s*\(",
    r"gmail\.googleapis\.com/\S*/(?:messages|drafts)/send",
]

_MESSAGE_PATTERNS = [
    r"\btwilio\b",
    r"api\.telegram\.org/bot\S*/send",
    r"hooks\.slack\.com/",
    r"\bchat\.postMessage\b",
    r"discord(?:app)?\.com/api/webhooks",
    r"graph\.facebook\.com/\S*/messages",
]

_HTTP_WRITE_PATTERNS = [
    r"\bcurl\b[^\n;|]*?(?:-X\s*|--request[\s=]+)['\"]?(?:POST|PUT|PATCH|DELETE)\b",
    r"\bcurl\b[^\n;|]*?\s(?:-d|--data(?:-raw|-binary|-urlencode)?|-F|--form|--json|-T|--upload-file)(?=[\s=@'\"])",
    r"\bwget\b[^\n;|]*?--(?:post-data|post-file|body-data|method[\s=]+['\"]?(?:POST|PUT|PATCH|DELETE))",
    r"\bhttps?\s+(?:POST|PUT|PATCH|DELETE)\s",
    r"\b(?:requests|httpx|aiohttp)\.(?:post|put|patch|delete)\s*\(",
    r"\bSession\(\)\s*\.\s*(?:post|put|patch|delete)\s*\(",
    r"\.(?:post|put|patch|delete)\s*\(\s*f?['\"]https?://",
    r"\bmethod\s*=\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]",
    r"\burlopen\s*\([^)]*\bdata\s*=",
]

_EMAIL_RE = [re.compile(p, _FLAGS) for p in _EMAIL_PATTERNS]
_MESSAGE_RE = [re.compile(p, _FLAGS) for p in _MESSAGE_PATTERNS]
_HTTP_WRITE_RE = [re.compile(p, _FLAGS) for p in _HTTP_WRITE_PATTERNS]

_URL_HOST_RE = re.compile(r"https?://([^/\s'\"`:)]+)", re.IGNORECASE)
_INTERNAL_HOST_RE = re.compile(
    r"^(?:localhost|0\.0\.0\.0|127(?:\.\d+){3}|\[?::1\]?|"
    r"[\w.-]+\.svc(?:\.cluster\.local)?|[\w.-]+\.cluster\.local)$",
    re.IGNORECASE,
)
# POST endpoints that only read (search / query APIs).
_READ_ONLY_POST_RE = re.compile(
    r"api\.notion\.com/v1/(?:search\b|databases/[^/\s'\"]+/query\b)",
    re.IGNORECASE,
)

# `python3 x.py`, `bash -e run.sh`, `node a.js`, `./send.sh`
_SCRIPT_RUN_RE = re.compile(
    r"(?:^|[\s;|&(])(?:(?:python[\d.]*|bash|sh|zsh|node|ruby|perl)\s+(?:-\S+\s+)*)?"
    r"((?:\.{0,2}/)?[\w./~-]+\.(?:py|sh|bash|js|mjs|rb|pl))\b"
)
_MAX_SCRIPT_BYTES = 256 * 1024

OutboundMatch = Tuple[bool, Optional[str], Optional[str]]
_NONE: OutboundMatch = (False, None, None)


def _any(patterns, text: str) -> bool:
    return any(p.search(text) for p in patterns)


def detect_outbound_action(text: str) -> OutboundMatch:
    """Return (found, key, description) for an outbound action in ``text``.

    ``description`` is plain English for the approval prompt ("send an
    email"); the SmartBuddy plugin renders it in the user's language.
    """
    if not text:
        return _NONE
    if _any(_EMAIL_RE, text):
        return True, "outbound:email", "send an email"
    if _any(_MESSAGE_RE, text):
        return True, "outbound:message", "send a message to someone"
    if _any(_HTTP_WRITE_RE, text):
        hosts = [h.lower() for h in _URL_HOST_RE.findall(text)]
        external = [h for h in hosts if not _INTERNAL_HOST_RE.match(h)]
        if hosts and not external:
            return _NONE  # only talks to the platform itself
        if external and _READ_ONLY_POST_RE.search(text) and all(
            h == "api.notion.com" for h in external
        ):
            return _NONE
        target = external[0] if external else None
        return True, "outbound:http", (
            f"send data to {target}" if target else "send data to an online service"
        )
    return _NONE


def _script_paths(command: str) -> list[str]:
    paths = []
    for m in _SCRIPT_RUN_RE.finditer(command):
        paths.append(m.group(1))
    return paths


def _read_script(raw: str, cwd: Optional[str]) -> Optional[str]:
    expanded = os.path.expanduser(raw)
    candidates = []
    if os.path.isabs(expanded):
        candidates.append(Path(expanded))
    else:
        bases = [cwd or os.getenv("TERMINAL_CWD") or os.getcwd()]
        hermes_home = os.getenv("HERMES_HOME")
        if hermes_home:
            bases += [hermes_home, os.path.join(hermes_home, "scripts")]
        candidates += [Path(b) / expanded for b in bases if b]
    for path in candidates:
        try:
            if path.is_file():
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(_MAX_SCRIPT_BYTES)
        except OSError:
            continue
    return None


def detect_outbound_command(command: str, cwd: Optional[str] = None) -> OutboundMatch:
    """Like :func:`detect_outbound_action`, but also scans the local script
    files the command runs (``python send.py``) — the agent usually writes the
    code to a file first, so the command line alone shows nothing."""
    found = detect_outbound_action(command)
    if found[0]:
        return found
    for raw in _script_paths(command):
        content = _read_script(raw, cwd)
        if content:
            found = detect_outbound_action(content)
            if found[0]:
                return found
    return _NONE


def detect_outbound_script_file(path: str) -> OutboundMatch:
    """Scan one script file (cron jobs run their scripts directly)."""
    content = _read_script(path, None)
    return detect_outbound_action(content or "")


__all__ = [
    "detect_outbound_action",
    "detect_outbound_command",
    "detect_outbound_script_file",
]
