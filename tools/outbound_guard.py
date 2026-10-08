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
import shlex
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

_URL_HOST_RE = re.compile(r"https?://(?:[^/\s'\"`@]*@)?([^/\s'\"`:)]+)", re.IGNORECASE)
# A host that may be always-allowed: a plain DNS name, not a template.
_PLAIN_HOST_RE = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")

# Writing to these APIs publishes or sends something in the user's name
# (social posts, mail, chat messages): treated like messages — always asked,
# never always-allowed. A host matches itself and its subdomains.
PUBLISH_AS_USER_HOSTS = frozenset({
    # social posting
    "api.twitter.com", "api.x.com", "graph.facebook.com", "graph.instagram.com",
    "api.linkedin.com", "weibo.com", "threads.net",
    # mail / message sending
    "gmail.googleapis.com", "graph.microsoft.com", "api.sendgrid.com",
    "api.mailgun.net", "api.postmarkapp.com", "slack.com", "discord.com",
    "discordapp.com", "api.telegram.org", "graph.whatsapp.com", "whatsapp.net",
    "api.twilio.com",
})
_INTERNAL_HOST_RE = re.compile(
    r"^(?:localhost|0\.0\.0\.0|127(?:\.\d+){3}|\[?::1\]?|"
    r"[\w.-]+\.svc(?:\.cluster\.local)?|[\w.-]+\.cluster\.local)$",
    re.IGNORECASE,
)
# Notion's search / query APIs are POSTs that only read. Scripts usually build
# the URL from a base (f"{API_URL}/search"), so look for the endpoint path and
# for any write endpoint instead of one full URL.
_NOTION_READ_RE = re.compile(
    r"/(?:search|databases/[^/\s'\"]+/query)\b", re.IGNORECASE)
_NOTION_WRITE_RE = re.compile(
    r"\b(?:PATCH|DELETE)\b|\.(?:patch|delete)\s*\(|/children\b|"
    r"/(?:pages|databases|comments)['\"]",
    re.IGNORECASE,
)

# --- Literal write targets (who an always-allowed host covers) ---------------
# A host the user always-allowed covers a command only when EVERY write in it
# has a literal target URL on that host. A URL elsewhere (a comment, a header,
# an unrelated string) must never vouch for a write to a variable.
_URL_HEAD_RE = re.compile(
    r"^https?://(?:[^/@{}\s'\"]*@)?([A-Za-z0-9.-]+)(?::\d+)?(?:/|$)")
_PY_WRITE_CALL_RE = re.compile(
    r"(?P<generic>\.request\s*\()|(?P<urllib>\bRequest\s*\()|"
    r"[\w)\]]*\.(?:post|put|patch|delete)\s*\(")
_PY_LITERAL_ARG_RE = re.compile(
    r"\s*(?:url\s*=\s*)?([rRuUfFbB]{0,2})(['\"])(https?://[^'\"\n]*)\2\s*(?:,|$)")
_WRITE_METHOD_RE = re.compile(r"['\"](?:POST|PUT|PATCH|DELETE)['\"]", re.IGNORECASE)
_SHELL_TOOL_RE = re.compile(r"(?<![\w./-])(curl|wget|https?)(?=\s)")
_SHELL_SEGMENT_END_RE = re.compile(r"[\n;|&]")
# curl / wget not written as a shell call (e.g. subprocess.run(["curl", ...])):
# its target can't be read, so it never counts as literal.
_SHELL_TOOL_UNPARSED_RE = re.compile(r"(?<![\w-])(?:curl|wget)(?![\w-])(?!\s)")
_CURL_VALUE_FLAGS = frozenset({
    "-X", "--request", "-H", "--header", "-d", "--data", "--data-raw",
    "--data-binary", "--data-urlencode", "--data-ascii", "-F", "--form",
    "--form-string", "--json", "-T", "--upload-file", "-o", "--output", "-u",
    "--user", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c",
    "--cookie-jar", "-w", "--write-out", "-m", "--max-time", "--connect-timeout",
    "--retry", "--oauth2-bearer", "-r", "--range", "--limit-rate", "--cacert",
    "--cert", "--key", "-E",
})
# Flags that send the request somewhere other than the URL's host.
_CURL_REDIRECT_FLAGS = frozenset({
    "-x", "--proxy", "--preproxy", "--resolve", "--connect-to", "-K", "--config",
    "--socks4", "--socks4a", "--socks5", "--socks5-hostname", "--unix-socket",
})
_WGET_VALUE_FLAGS = frozenset({
    "-O", "--output-document", "-o", "--output-file", "--post-data", "--post-file",
    "--body-data", "--body-file", "--method", "--header", "-U", "--user-agent",
    "--user", "--password", "--http-user", "--http-password", "-t", "--tries",
    "-T", "--timeout", "--referer", "--load-cookies", "--save-cookies", "-P",
    "--directory-prefix",
})
_WGET_REDIRECT_FLAGS = frozenset({"-e", "--execute", "-i", "--input-file", "-B", "--base"})
_HTTPIE_VALUE_FLAGS = frozenset({
    "-a", "--auth", "-A", "--auth-type", "--session", "--session-read-only",
    "-o", "--output", "--verify", "--cert", "--cert-key", "--timeout",
})
_HTTPIE_REDIRECT_FLAGS = frozenset({"--proxy"})
_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})


def _url_host(url: str, allow_braces: bool = True) -> Optional[str]:
    """Host of a literal ``scheme://host[:port](/...)`` URL, else None."""
    m = _URL_HEAD_RE.match(url)
    if not m or (not allow_braces and "{" in m.group(0)):
        return None
    host = m.group(1).lower()
    return host if _PLAIN_HOST_RE.match(host) else None


def _call_args(text: str, open_idx: int) -> Tuple[str, int]:
    """Text inside the parentheses opened at ``open_idx`` and the end index."""
    depth, quote, i = 0, None, open_idx
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i + 1
        i += 1
    return text[open_idx + 1:], len(text)


def _python_write_sites(text: str) -> list:
    sites = []
    for m in _PY_WRITE_CALL_RE.finditer(text):
        args, end = _call_args(text, m.end() - 1)
        if m.group("generic"):
            # session.request("POST", url): never attributed to a host
            if _WRITE_METHOD_RE.search(args):
                sites.append((m.start(), end, None))
            continue
        if m.group("urllib") and "," not in args:
            continue  # urllib Request(url) alone is a GET
        lit = _PY_LITERAL_ARG_RE.match(args)
        host = None
        if lit:
            host = _url_host(lit.group(3), allow_braces="f" not in lit.group(1).lower())
        sites.append((m.start(), end, host))
    return sites


def _shell_targets(tokens: list, value_flags, redirect_flags, httpie: bool = False):
    """Literal target hosts of one curl / wget / httpie call, or None."""
    targets, i, method_seen = [], 1, False
    while i < len(tokens):
        tok = tokens[i]
        name = tok.split("=", 1)[0]
        if tok.startswith("-") and len(tok) > 1:
            if name in redirect_flags or tok[:2] in redirect_flags:
                return None
            if name == "--url":
                targets.append(tok.split("=", 1)[1] if "=" in tok else
                               (tokens[i + 1] if i + 1 < len(tokens) else ""))
                i += 1 if "=" in tok else 2
                continue
            if "=" not in tok and (tok in value_flags):
                i += 2
                continue
            i += 1
            continue
        if httpie:
            if not method_seen and tok in _HTTP_METHODS:
                method_seen = True
                i += 1
                continue
            targets.append(tok)
            break  # the rest are request items
        targets.append(tok)
        i += 1
    if not targets:
        return None
    hosts = [_url_host(t, allow_braces=False) for t in targets]
    return None if None in hosts else hosts


def _shell_write_sites(text: str) -> list:
    sites = []
    for m in _SHELL_TOOL_RE.finditer(text):
        end_m = _SHELL_SEGMENT_END_RE.search(text, m.start())
        end = end_m.start() if end_m else len(text)
        segment = text[m.start():end]
        if not _any(_HTTP_WRITE_RE, segment):
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
            sites.append((m.start(), end, None))
            continue
        tool = m.group(1).lower()
        if tool == "curl":
            hosts = _shell_targets(tokens, _CURL_VALUE_FLAGS, _CURL_REDIRECT_FLAGS)
        elif tool == "wget":
            hosts = _shell_targets(tokens, _WGET_VALUE_FLAGS, _WGET_REDIRECT_FLAGS)
        else:
            hosts = _shell_targets(tokens, _HTTPIE_VALUE_FLAGS, _HTTPIE_REDIRECT_FLAGS, httpie=True)
        if hosts is None or len(set(hosts)) != 1:
            sites.append((m.start(), end, None))
        else:
            sites.append((m.start(), end, hosts[0]))
    return sites


def _literal_write_host(text: str) -> Optional[str]:
    """The one host every write in ``text`` literally targets, else None."""
    if _SHELL_TOOL_UNPARSED_RE.search(text):
        return None
    sites = _python_write_sites(text) + _shell_write_sites(text)
    for pattern in _HTTP_WRITE_RE:
        for m in pattern.finditer(text):
            if not any(m.start() < end and m.end() > start for start, end, _ in sites):
                return None  # a write we can't attribute
    hosts = {host for _, _, host in sites}
    if len(hosts) != 1 or None in hosts:
        return None
    return hosts.pop()


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
        if (external and all(h == "api.notion.com" for h in external)
                and _NOTION_READ_RE.search(text) and not _NOTION_WRITE_RE.search(text)):
            return _NONE
        target = external[0] if external else None
        description = (
            f"send data to {target}" if target else "send data to an online service"
        )
        publish = next((h for h in external if is_publish_host(h)), None)
        if publish:
            return True, "outbound:publish", f"send data to {publish}"
        # Every write literally targets the one external host the text names:
        # keyed by host so it can be always-allowed.
        host = _literal_write_host(text)
        if host and set(external) == {host}:
            return True, f"outbound:http:{host}", description
        return True, "outbound:http", description
    return _NONE


def is_publish_host(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in PUBLISH_AS_USER_HOSTS)


def allowable_http_host(key: Optional[str]) -> Optional[str]:
    """The host of an ``outbound:http:<host>`` key the user may always-allow,
    else None (email / message / publish keys never are)."""
    prefix = "outbound:http:"
    if not isinstance(key, str) or not key.startswith(prefix):
        return None
    host = key[len(prefix):]
    if not _PLAIN_HOST_RE.match(host) or is_publish_host(host):
        return None
    return host


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
    matches = [detect_outbound_action(command)]
    for raw in _script_paths(command):
        content = _read_script(raw, cwd)
        if content:
            matches.append(detect_outbound_action(content))
    matches = [m for m in matches if m[0]]
    if not matches:
        return _NONE
    # The strictest wins; a host key holds only if every part agrees on it.
    for key in ("outbound:email", "outbound:message", "outbound:publish"):
        for m in matches:
            if m[1] == key:
                return m
    if len({m[1] for m in matches}) == 1:
        return matches[0]
    return True, "outbound:http", matches[0][2]


def detect_outbound_script_file(path: str) -> OutboundMatch:
    """Scan one script file (cron jobs run their scripts directly)."""
    content = _read_script(path, None)
    return detect_outbound_action(content or "")


__all__ = [
    "PUBLISH_AS_USER_HOSTS",
    "allowable_http_host",
    "detect_outbound_action",
    "detect_outbound_command",
    "detect_outbound_script_file",
    "is_publish_host",
]
