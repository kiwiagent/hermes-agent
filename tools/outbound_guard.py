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
from typing import NamedTuple, Optional, Tuple
from urllib.parse import urlsplit

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
    # himalaya (SmartBuddy mail skill): message send/write/compose/reply/forward,
    # template send — also as a subprocess argument list. Reads don't match.
    r"""\bhimalaya\b[^\n;|&]*?\b(?:message|msg|template|tpl)['"]?[\s,'"]+(?:send|write|compose|reply|forward|fwd)\b""",
    # kiwiagent (security review 2026-10-27): the same with the subcommand
    # split by quotes ('mess''age' send), or himalaya hidden in a variable.
    r"""\bhimalaya\b[^\n;|&]*?(?:mess|msg|templ|tpl)['"a-z]*[\s,]+['"]?(?:send|write|compose|reply|forward|fwd)\b""",
    # The installed CLI's own source is exempt from the scan (see
    # _is_platform_cli): no rule applies to that file's text, so the mail
    # client it configures is judged on the command line that runs it. The
    # shipped CLI has no mail-send subcommand (its `mail unsubscribe` is
    # cardless by the plugin's contract test in smartbuddy-hermes-plugin
    # tests/test_sb_cli.py); one that ships needs a rule of its own here.
]

# himalaya hidden in a variable: ``client = "himalaya"`` then
# ``client.message.send()`` is a send. A keyword argument that only *labels*
# the client for a human is not — an argparse
# ``help="himalaya config for every connected mailbox"`` was the 2026-10-28
# card that showed on every SmartBuddy turn, and ``usage=``/``prog=`` etc. read
# the same way. What makes it a label is the prose, or an argument-parser
# call: ``help="himalaya config …"`` in any call and ``ArgumentParser(prog=
# "himalaya")`` are labels, while ``send(prog="himalaya")`` passes the client
# and still asks — the name alone does not exempt a bare value. An assignment
# in a call's argument list with a label name is a label, and a signature
# default is not an argument. A spaced ``x.description = …`` attribute write
# is a label because the attribute *is* one of those names; every other
# spelling counts, including a bare ``cfg.client=…`` and a spaced
# ``self.mail = …`` that holds the client.
_HIMALAYA_VAR_RE = re.compile(r"""(?<!\w)([a-z_]\w*)=['"]?himalaya\b""", _FLAGS)
_HIMALAYA_SPACED_VAR_RE = re.compile(
    r"""(?<!\w)([a-z_]\w*)\s*=\s*['"]?himalaya\b""", _FLAGS)
_LABEL_KWARGS = frozenset(
    {"help", "description", "metavar", "dest", "usage", "epilog", "prog"})
# A label reads on as prose (``"himalaya config for …"``) or is a keyword of
# the argument parser itself (``ArgumentParser(prog="himalaya")``).
_PROSE_RE = re.compile(r"""[a-z_]\w*\s*=\s*['"]?himalaya\b\s""", _FLAGS)
_PARSER_CALLEE_RE = re.compile(
    r"(?:^|\.)(?:add_argument|add_parser|argumentparser)$", _FLAGS)
_SIGNATURE_RE = re.compile(r"\b(?:def|class)\s+\w+(?:\[[^\]\n]*\])?\s*$")
_ATTRIBUTE_RE = re.compile(r"[\w)\]]\.[ \t]*\Z")

# What a bracket counter must step over rather than count: strings, comments,
# docstrings — matched at C speed, so a label-dense file costs one scan.
_STRUCTURE_RE = re.compile(
    r'"""(?:\\.|(?!""")[\s\S])*"""'
    r"|'''(?:\\.|(?!''')[\s\S])*'''"
    r"|#[^\n]*"
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'"
    r"|[()\[\]{}]"
)


def _callee(tail: str) -> str:
    """The dotted name a call's ``(`` belongs to, lower-cased (empty if none)."""
    tail = tail.rstrip()
    start = len(tail)
    while start and (tail[start - 1].isalnum() or tail[start - 1] in "_."):
        start -= 1
    return tail[start:].lower()


def _himalaya_hidden_in_a_variable(text: str) -> bool:
    """True when the text names the mail client where it could be sent with.

    A label for a human — prose in a keyword argument, or the argument
    parser's own keywords — does not count; see the patterns' comment.
    """
    mentions = sorted(
        [(m.start(), m.group(1).lower(), False) for m in _HIMALAYA_VAR_RE.finditer(text)]
        + [(m.start(), m.group(1).lower(), True)
           for m in _HIMALAYA_SPACED_VAR_RE.finditer(text)]
    )
    if not mentions:
        return False
    calls: list[tuple[bool, str]] = []  # per open bracket: def/class head, callee
    last = ""  # last visible character before the cursor
    tail = ""  # visible text, for the def/class and callee lookbacks
    tokens = _STRUCTURE_RE.finditer(text)
    token = next(tokens, None)
    cursor = 0
    for start, name, spaced in mentions:
        while token is not None and token.start() < start:
            raw = text[cursor:token.start()]
            tail = (tail + raw)[-256:]
            run = raw.rstrip()
            if run:
                last = run[-1]
            bracket = token.group() if token.group() in "([{)]}" else ""
            if bracket:
                if bracket in "([{":
                    if bracket == "(" and _SIGNATURE_RE.search(tail):
                        calls.append((True, ""))
                    else:
                        calls.append((False, _callee(tail)))
                elif calls:
                    calls.pop()
                last = bracket
                tail = (tail + bracket)[-256:]
            cursor = token.end()
            token = next(tokens, None)
        raw = text[cursor:start]
        tail = (tail + raw)[-256:]
        run = raw.rstrip()
        if run:
            last = run[-1]
        cursor = max(cursor, start)
        if name in _LABEL_KWARGS:
            # An argument boundary inside a call makes a label; a signature's
            # default is not an argument, so ``def send(prog="himalaya")``
            # counts, and so does a bare value passed to an ordinary callee.
            if calls and not calls[-1][0] and last and last in ",([":
                if (_PROSE_RE.match(text, start)
                        or _PARSER_CALLEE_RE.search(calls[-1][1])):
                    continue
            # ``x.description = "himalaya login"`` is prose, not a client.
            elif spaced and _ATTRIBUTE_RE.search(tail):
                continue
        return True
    return False


_MESSAGE_PATTERNS = [
    r"\btwilio\b",
    r"api\.telegram\.org/bot\S*/send",
    r"hooks\.slack\.com/",
    r"\bchat\.postMessage\b",
    r"discord(?:app)?\.com/api/webhooks",
    r"graph\.facebook\.com/\S*/messages",
]

# SmartBuddy's platform CLI (kiwiagent 2026-10-27): its writes go to an
# internal address, so the HTTP rules let them through — judged by subcommand
# instead. Also matched as a subprocess argument list. Reads don't match.
_SB = r"""\bsb(?:\.py)?['"]?[\s,'"]+"""

_CALENDAR_PATTERNS = [
    _SB + r"""gcal['"]?[\s,'"]+(?:add|change|delete)\b""",
]
# Posting on / deleting from the user's Facebook Page. Boosts are created
# paused (the user starts them in the app), so preparing one isn't here.
_PUBLISH_CLI_PATTERNS = [
    _SB + r"""facebook['"]?[\s,'"]+(?:post|delete)\b""",
]

# The platform CLI as installed: reading its source (help text names every
# subcommand) must not count as running them.
_PLATFORM_CLI = "/opt/hermes/plugins/platforms/smartbuddy/sb.py"


def _is_platform_cli(path: str) -> bool:
    """``path`` is the installed platform CLI itself.

    Only that one file is exempt: its help text and docstrings name every
    subcommand, the mail client behind a mailbox and the HTTP calls the plugin
    makes to the platform itself — none of that is an action. A file beside it
    is the buddy's business like any other script, and running the CLI is
    judged by the command line that runs it. ``path`` comes from
    :func:`_read_script` already resolved with ``realpath``, so the same file
    reached through a symlink or a relative path is recognised too.
    """
    return os.path.realpath(path) == os.path.realpath(os.path.expanduser(_PLATFORM_CLI))


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
    # JavaScript: fetch / axios / node http(s).request
    r"\bmethod\s*:\s*['\"`](?:POST|PUT|PATCH|DELETE)['\"`]",
    r"\bfetch\s*\([^)]*?\bmethod\s*:(?!\s*['\"`](?:GET|HEAD|OPTIONS)['\"`])",
    r"\b(?:axios|got|ky|superagent|needle)\s*\.\s*(?:post|put|patch|delete)\s*\(",
]

_EMAIL_RE = [re.compile(p, _FLAGS) for p in _EMAIL_PATTERNS]
_MESSAGE_RE = [re.compile(p, _FLAGS) for p in _MESSAGE_PATTERNS]
_HTTP_WRITE_RE = [re.compile(p, _FLAGS) for p in _HTTP_WRITE_PATTERNS]
_CALENDAR_RE = [re.compile(p, _FLAGS) for p in _CALENDAR_PATTERNS]
_PUBLISH_CLI_RE = [re.compile(p, _FLAGS) for p in _PUBLISH_CLI_PATTERNS]

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
# the URL from a base (f"{API_URL}/search"), so each write's URL is resolved
# through a base constant assigned once, then its path is checked.
_NOTION_READ_PATH_RE = re.compile(
    r"^/v1/(?:search|databases/[^/]+/query)/?$", re.IGNORECASE)
_NOTION_WRITE_RE = re.compile(
    r"\b(?:PATCH|DELETE)\b|\.(?:patch|delete)\s*\(|/children\b|"
    r"/(?:pages|databases|comments)['\"]",
    re.IGNORECASE,
)

# --- Literal write targets ----------------------------------------------------
# An always-allowed host, the internal-host exemption and the Notion read-only
# exemption only apply when EVERY write has a literal target URL. A URL
# elsewhere (a comment, a header, an unrelated string) never vouches for a
# write to a variable.
_URL_HEAD_RE = re.compile(
    r"^https?://(?:[^/@{}\s'\"`]*@)?([A-Za-z0-9.-]+)(?::\d+)?(?:/|$)")
_WRITE_CALL_RE = re.compile(
    r"(?P<generic>\.request\s*\()|(?P<urllib>\bRequest\s*\()|(?P<fetch>\bfetch\s*\()|"
    r"[\w)\]]*\.(?P<verb>post|put|patch|delete)\s*\(")
_LITERAL_ARG_RE = re.compile(
    r"\s*(?:url\s*=\s*)?([rRuUfFbB]{0,2})(['\"`])([^'\"`\n]*)\2\s*(?:,|$)")
_PY_METHOD_KW_RE = re.compile(r"\bmethod\s*=\s*(['\"])(\w+)\1")
_JS_METHOD_RE = re.compile(r"\bmethod\s*:\s*(?:(['\"`])(\w+)\1)?")
_WRITE_METHOD_RE = re.compile(r"['\"`](?:POST|PUT|PATCH|DELETE)['\"`]", re.IGNORECASE)
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_FORMATTED_HEAD_RE = re.compile(r"^\$?\{(\w+)\}(.*)$", re.S)
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
_METHOD_FLAGS = frozenset({"-X", "--request", "--method"})
_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})


class _Site(NamedTuple):
    """One write call: span, target URL (literal or through a base URL
    constant bound once; None when unknown) and upper-case method."""
    start: int
    end: int
    url: Optional[str]
    method: Optional[str]


def _url_host(url: Optional[str], allow_braces: bool = True) -> Optional[str]:
    """Host of a literal ``scheme://host[:port](/...)`` URL, else None."""
    m = _URL_HEAD_RE.match(url or "")
    if not m or (not allow_braces and "{" in m.group(0)):
        return None
    host = m.group(1).lower()
    if _PLAIN_HOST_RE.match(host) or _INTERNAL_HOST_RE.match(host):
        return host
    return None


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
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i + 1
        i += 1
    return text[open_idx + 1:], len(text)


def _base_constant(name: str, text: str) -> Optional[str]:
    """The literal URL ``name`` is bound to, when it is bound exactly once
    (``BASE = "https://..."`` / ``const BASE = "..."``) and never rebound,
    shadowed or deleted. Anything else: None."""
    word = re.escape(name)
    assign = re.compile(
        rf"^[ \t]*(?:(?:const|let|var)\s+)?{word}\s*(?::[^=\n]*)?=\s*"
        rf"(['\"])(https?://[^'\"\n{{}}$]*)\1\s*;?\s*$", re.M)
    found = assign.findall(text)
    bindings = re.findall(rf"\b{word}\s*(?::[^=\n]*)?(?:[-+*/%|&^@]|//|:)?=(?!=)", text)
    shadowed = re.search(
        rf"(?:\b(?:def|lambda|for|as|import|global|nonlocal|del|class|function)\b|=>)"
        rf"[^\n]*\b{word}\b|\b{word}\b[^\n]*=>", text)
    if len(found) != 1 or len(bindings) != 1 or shadowed:
        return None
    return found[0][1]


def _literal_target(args: str, text: str) -> Optional[str]:
    """A call's literal target URL, also through a base constant bound once."""
    lit = _LITERAL_ARG_RE.match(args)
    if not lit:
        return None
    prefix, quote, content = lit.group(1).lower(), lit.group(2), lit.group(3)
    formatted = "f" in prefix or quote == "`"
    url = content if _url_host(content, allow_braces=not formatted) else None
    if url or not formatted:
        return url
    head = _FORMATTED_HEAD_RE.match(content)
    base = _base_constant(head.group(1), text) if head else None
    return (base + head.group(2)) if base else None


def _code_write_sites(text: str) -> list:
    sites = []
    for m in _WRITE_CALL_RE.finditer(text):
        args, end = _call_args(text, m.end() - 1)
        if m.group("generic"):
            # session.request("POST", url) / https.request({...}): never attributed
            if _WRITE_METHOD_RE.search(args):
                sites.append(_Site(m.start(), end, None, None))
            continue
        if m.group("urllib"):
            if "," not in args:
                continue  # urllib Request(url) alone is a GET
            kw = _PY_METHOD_KW_RE.search(args)
            method = kw.group(2).upper() if kw else (None if "method" in args else "POST")
        elif m.group("fetch"):
            js = _JS_METHOD_RE.search(args)
            if not js:
                continue  # fetch(url) is a GET
            method = js.group(2).upper() if js.group(2) else None
            if method in _READ_METHODS:
                continue
        else:
            method = m.group("verb").upper()
        sites.append(_Site(m.start(), end, _literal_target(args, text), method))
    return sites


def _shell_targets(tokens: list, value_flags, redirect_flags, httpie: bool = False):
    """(literal target URLs, method) of one curl / wget / httpie call; the
    URL list is None when any target is not a literal URL."""
    targets, i, method = [], 1, None
    while i < len(tokens):
        tok = tokens[i]
        name, _, attached = tok.partition("=")
        if tok.startswith("-") and len(tok) > 1:
            if name in redirect_flags or tok[:2] in redirect_flags:
                return None, method
            if name == "--url":
                targets.append(attached if attached else
                               (tokens[i + 1] if i + 1 < len(tokens) else ""))
                i += 1 if attached else 2
                continue
            if name in _METHOD_FLAGS and attached:
                method = attached.upper()
            elif tok.startswith("-X") and len(tok) > 2:
                method = tok[2:].upper()
            if not attached and tok in value_flags:
                if tok in _METHOD_FLAGS and i + 1 < len(tokens):
                    method = tokens[i + 1].upper()
                i += 2
                continue
            i += 1
            continue
        if httpie:
            if method is None and tok in _HTTP_METHODS:
                method = tok
                i += 1
                continue
            targets.append(tok)
            break  # the rest are request items
        targets.append(tok)
        i += 1
    if not targets or any(_url_host(t, allow_braces=False) is None for t in targets):
        return None, method
    return targets, method


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
            sites.append(_Site(m.start(), end, None, None))
            continue
        tool = m.group(1).lower()
        if tool == "curl":
            urls, method = _shell_targets(tokens, _CURL_VALUE_FLAGS, _CURL_REDIRECT_FLAGS)
        elif tool == "wget":
            urls, method = _shell_targets(tokens, _WGET_VALUE_FLAGS, _WGET_REDIRECT_FLAGS)
        else:
            urls, method = _shell_targets(
                tokens, _HTTPIE_VALUE_FLAGS, _HTTPIE_REDIRECT_FLAGS, httpie=True)
        method = method or "POST"  # a write without -X sends data: POST
        for url in urls or [None]:
            sites.append(_Site(m.start(), end, url, method))
    return sites


def _write_sites(text: str) -> Optional[list]:
    """Every write call in ``text``, or None when a write can't be read."""
    if _SHELL_TOOL_UNPARSED_RE.search(text):
        return None
    sites = _code_write_sites(text) + _shell_write_sites(text)
    for pattern in _HTTP_WRITE_RE:
        for m in pattern.finditer(text):
            if not any(m.start() < s.end and m.end() > s.start for s in sites):
                return None  # a write we can't attribute
    return sites or None


def _literal_write_hosts(text: str) -> Optional[set]:
    """Hosts every write in ``text`` literally targets (directly or through a
    base URL constant bound once), else None."""
    sites = _write_sites(text)
    if not sites:
        return None
    hosts = {_url_host(s.url) for s in sites}
    return None if None in hosts else hosts


def _notion_read_only(text: str) -> bool:
    """Every write is a POST to a Notion read endpoint (search / db query)."""
    if _NOTION_WRITE_RE.search(text):
        return False
    sites = _write_sites(text)
    if not sites:
        return False
    for s in sites:
        if s.method != "POST" or _url_host(s.url) != "api.notion.com":
            return False
        path = urlsplit(s.url).path
        if not _NOTION_READ_PATH_RE.match(path):
            return False
    return True


# `python3 x.py`, `bash -e run.sh`, `node a.js`, `./send.sh` — also as a
# subprocess argument list.
_SCRIPT_EXT = r"\.(?:py|sh|bash|js|mjs|cjs|jsx|tsx|mts|cts|ts|rb|pl)"
_SCRIPT_RUN_RE = re.compile(
    r"(?:^|[\s;|&(])(?:(?:python[\d.]*|bash|sh|zsh|node|ruby|perl)\s+(?:-\S+\s+)*)?"
    r"""((?:\.{0,2}/)?[\w./~-]+""" + _SCRIPT_EXT + r""")\b"""
)
# The same with the path quoted (`python3 "my script.py"`), which used to skip
# the scan. A quoted *command* (`bash -c "python3 send.py"`) matches here too,
# but it names no file; the pass above finds the script inside it.
_SCRIPT_QUOTED_RE = re.compile(r"""['"]([^'"\n]+""" + _SCRIPT_EXT + r""")['"]""")
_MAX_SCRIPT_BYTES = 256 * 1024

OutboundMatch = Tuple[bool, Optional[str], Optional[str]]
_NONE: OutboundMatch = (False, None, None)


def _any(patterns, text: str) -> bool:
    return any(p.search(text) for p in patterns)


# curl -G / --get sends -d / --data-urlencode values as the URL query (a GET):
# map lookups and web searches. Short-flag clusters only count when every
# other letter is a flag without an argument (-sG, -GsS; not -XGET).
_CURL_SEGMENT_SPLIT_RE = re.compile(r"(\n|;|\||&)")
_CURL_GET_FLAG_RE = re.compile(r"(?:^|\s)(?:-[sSLkfivqg]*G[sSLkfivqg]*|--get)(?=\s|$)")
_CURL_GET_WRITE_RE = re.compile(
    r"(?:^|\s)(?:-X\s*['\"]?|--request[\s=]+['\"]?)(?![Gg][Ee][Tt]\b|[Hh][Ee][Aa][Dd]\b)"
    r"|(?:^|\s)(?:-[a-zA-Z]*[FT]|--(?:form|upload-file|json)\b)"
)


def _without_curl_get_reads(text: str) -> str:
    """``text`` with each curl -G / --get lookup blanked out, so its query
    data isn't taken for a write. A segment that also sets a write method or
    uploads (-X POST, -T, -F, --json) is kept."""
    parts = _CURL_SEGMENT_SPLIT_RE.split(text)
    for i in range(0, len(parts), 2):
        part = parts[i]
        if (re.search(r"\bcurl\b", part) and _CURL_GET_FLAG_RE.search(part)
                and not _CURL_GET_WRITE_RE.search(part)):
            parts[i] = ""
    return "".join(parts)


def detect_outbound_action(text: str, *, platform_cli_source: bool = False) -> OutboundMatch:
    """Return (found, key, description) for an outbound action in ``text``.

    ``description`` is plain English for the approval prompt ("send an
    email"); the SmartBuddy plugin renders it in the user's language.
    ``platform_cli_source``: ``text`` is the installed CLI's own source, which
    only *describes* what its subcommands do — those count on a command line
    or in a script of the buddy's own, never in the plugin's own source.
    Skipping it here matters for every pattern, not just the CLI ones: a help
    string naming the mail client ("himalaya config for every connected
    mailbox") is not a hidden way to send an email.
    """
    if not text or platform_cli_source:
        return _NONE
    if _any(_EMAIL_RE, text) or _himalaya_hidden_in_a_variable(text):
        return True, "outbound:email", "send an email"
    if _any(_MESSAGE_RE, text):
        return True, "outbound:message", "send a message to someone"
    if _any(_PUBLISH_CLI_RE, text):
        return True, "outbound:publish", "post on Facebook"
    if _any(_CALENDAR_RE, text):
        return True, "outbound:calendar", "change your calendar"
    text = _without_curl_get_reads(text)
    if _any(_HTTP_WRITE_RE, text):
        hosts = [h.lower() for h in _URL_HOST_RE.findall(text)]
        external = [h for h in hosts if not _INTERNAL_HOST_RE.match(h)]
        literal = _literal_write_hosts(text)
        if hosts and not external and literal and all(
                _INTERNAL_HOST_RE.match(h) for h in literal):
            return _NONE  # every write literally goes to the platform itself
        if (external and all(h == "api.notion.com" for h in external)
                and _notion_read_only(text)):
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
        if literal and len(literal) == 1 and set(external) == literal:
            host = next(iter(literal))
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
    paths = [m.group(1) for m in _SCRIPT_RUN_RE.finditer(command)]
    paths += [m.group(1) for m in _SCRIPT_QUOTED_RE.finditer(command)]
    return list(dict.fromkeys(paths))


def _read_script(raw: str, cwd: Optional[str]) -> Optional[tuple[str, str]]:
    """(realpath of the script ``raw`` names, its source), or None.

    The path comes back with the source because the scan needs to know *whose*
    code it is reading: the platform CLI's own source describes the actions
    instead of taking them (see :func:`_is_platform_cli`)."""
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
                with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                    return os.path.realpath(str(path)), f.read(_MAX_SCRIPT_BYTES)
        except OSError:
            continue
    return None


def detect_outbound_command(command: str, cwd: Optional[str] = None) -> OutboundMatch:
    """Like :func:`detect_outbound_action`, but also scans the local script
    files the command runs (``python send.py``) — the agent usually writes the
    code to a file first, so the command line alone shows nothing."""
    matches = [detect_outbound_action(command)]
    for raw in _script_paths(command):
        script = _read_script(raw, cwd)
        if script:
            path, source = script
            matches.append(detect_outbound_action(
                source, platform_cli_source=_is_platform_cli(path)))
    matches = [m for m in matches if m[0]]
    if not matches:
        return _NONE
    # The strictest wins; a host key holds only if every part agrees on it.
    for key in ("outbound:email", "outbound:message", "outbound:publish", "outbound:calendar"):
        for m in matches:
            if m[1] == key:
                return m
    if len({m[1] for m in matches}) == 1:
        return matches[0]
    return True, "outbound:http", matches[0][2]


def detect_outbound_script_file(path: str) -> OutboundMatch:
    """Scan one script file that is run directly, not through a command line.

    Cron jobs pass their script text to the guard themselves, so nothing in
    this repository calls this function; it is here for hosts that run a file
    by path. The platform CLI's own file is exempt, like everywhere else."""
    script = _read_script(path, None)
    if not script:
        return _NONE
    resolved, source = script
    return detect_outbound_action(
        source, platform_cli_source=_is_platform_cli(resolved))


__all__ = [
    "PUBLISH_AS_USER_HOSTS",
    "allowable_http_host",
    "detect_outbound_action",
    "detect_outbound_command",
    "detect_outbound_script_file",
    "is_publish_host",
]
