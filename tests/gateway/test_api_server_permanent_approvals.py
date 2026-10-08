"""kiwiagent: GET / DELETE /api/approvals/permanent — the user's always-allowed
actions, listed and revoked from the SmartBuddy app (via the backend).

Email / message / publish keys are never listed (they can never be
always-allowed). Both routes need the API server key like the other /api routes.
"""

from urllib.parse import quote

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter, cors_middleware
from tools import approval as A

ROUTES = {("GET", "/api/approvals/permanent"), ("DELETE", "/api/approvals/permanent")}


def _make_adapter(api_key: str = "") -> APIServerAdapter:
    extra = {"key": api_key} if api_key else {}
    return APIServerAdapter(PlatformConfig(enabled=True, extra=extra))


def _create_app(adapter: APIServerAdapter) -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app["api_server_adapter"] = adapter
    for method, path, handler in adapter._http_route_table():
        if (method, path) in ROUTES:
            app.router.add_route(method, path, handler)
    return app


@pytest.fixture
def allowlist(monkeypatch):
    perm = {"outbound:http:api.notion.com", "recursive delete", "outbound:email"}
    saved = []
    monkeypatch.setattr(A, "_permanent_approved", perm)
    monkeypatch.setattr(A, "save_permanent_allowlist", lambda p: saved.append(set(p)))
    return perm, saved


def test_route_table_has_permanent_approval_routes():
    table = {(m, p) for m, p, _h in _make_adapter()._http_route_table()}
    assert ROUTES <= table


class TestGet:
    @pytest.mark.asyncio
    async def test_lists_items_without_hard_keys(self, allowlist):
        async with TestClient(TestServer(_create_app(_make_adapter()))) as cli:
            resp = await cli.get("/api/approvals/permanent")
            assert resp.status == 200
            assert await resp.json() == {"items": [
                {"key": "outbound:http:api.notion.com", "kind": "http", "target": "api.notion.com"},
                {"key": "recursive delete", "kind": "command", "target": "recursive delete"},
            ]}


class TestDelete:
    @pytest.mark.asyncio
    async def test_removes_key_from_memory_and_config(self, allowlist):
        perm, saved = allowlist
        key = quote("outbound:http:api.notion.com", safe="")
        async with TestClient(TestServer(_create_app(_make_adapter()))) as cli:
            resp = await cli.delete(f"/api/approvals/permanent?key={key}")
            assert resp.status == 200
            assert await resp.json() == {"removed": True}
        assert "outbound:http:api.notion.com" not in perm
        assert saved and "outbound:http:api.notion.com" not in saved[-1]

    @pytest.mark.asyncio
    async def test_key_with_space_is_url_decoded(self, allowlist):
        perm, _ = allowlist
        async with TestClient(TestServer(_create_app(_make_adapter()))) as cli:
            resp = await cli.delete(f"/api/approvals/permanent?key={quote('recursive delete')}")
            assert await resp.json() == {"removed": True}
        assert "recursive delete" not in perm

    @pytest.mark.asyncio
    async def test_unknown_key_not_removed(self, allowlist):
        _, saved = allowlist
        async with TestClient(TestServer(_create_app(_make_adapter()))) as cli:
            resp = await cli.delete("/api/approvals/permanent?key=outbound%3Ahttp%3Aexample.com")
            assert resp.status == 200
            assert await resp.json() == {"removed": False}
        assert saved == []

    @pytest.mark.asyncio
    async def test_missing_key_is_400(self, allowlist):
        async with TestClient(TestServer(_create_app(_make_adapter()))) as cli:
            resp = await cli.delete("/api/approvals/permanent")
            assert resp.status == 400


class TestAuth:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("method", ["GET", "DELETE"])
    async def test_requires_api_key(self, allowlist, method):
        perm, saved = allowlist
        async with TestClient(TestServer(_create_app(_make_adapter("sk-secret")))) as cli:
            url = "/api/approvals/permanent?key=recursive%20delete"
            resp = await cli.request(method, url)
            assert resp.status == 401
            resp = await cli.request(method, url, headers={"Authorization": "Bearer wrong"})
            assert resp.status == 401
        assert "recursive delete" in perm and saved == []

    @pytest.mark.asyncio
    async def test_valid_key_accepted(self, allowlist):
        async with TestClient(TestServer(_create_app(_make_adapter("sk-secret")))) as cli:
            resp = await cli.get("/api/approvals/permanent",
                                 headers={"Authorization": "Bearer sk-secret"})
            assert resp.status == 200
