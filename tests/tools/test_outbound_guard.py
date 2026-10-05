"""kiwiagent: outbound actions need the user's approval (SmartBuddy promise:
"Every action needs your approval").

Anything the buddy sends out in the user's name — email, messages to other
people, data written to an external service — is detected so it can always be
put in front of the user (never smart-auto-approved), and never runs from a
cron job where no one is there to approve it.
"""
import pytest

from tools.outbound_guard import detect_outbound_action, detect_outbound_command


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
        assert found and key == "outbound:http"
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
        assert found and key == "outbound:http"
