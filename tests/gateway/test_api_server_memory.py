"""kiwiagent: GET /api/memory — the buddy's memory entries for the SmartBuddy
app's 记 tab (via the backend). Read-only; needs the API server key like the
other /api routes.
"""

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter, cors_middleware
from tools import memory_tool as M

ROUTE = ("GET", "/api/memory")


def _make_adapter(api_key: str = "") -> APIServerAdapter:
    extra = {"key": api_key} if api_key else {}
    return APIServerAdapter(PlatformConfig(enabled=True, extra=extra))


def _create_app(adapter: APIServerAdapter) -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app["api_server_adapter"] = adapter
    for method, path, handler in adapter._http_route_table():
        if (method, path) == ROUTE:
            app.router.add_route(method, path, handler)
    return app


class _Store:
    memory_entries = ["Mia has swimming on Wednesdays", "Prefers replies before 9am"]
    user_entries = ["Lives in Remuera", "Doesn't eat pork"]


@pytest.fixture
def store(monkeypatch):
    monkeypatch.setattr(M, "load_on_disk_store", lambda: _Store())


def test_route_table_has_memory_route():
    table = {(m, p) for m, p, _h in _make_adapter()._http_route_table()}
    assert ROUTE in table


@pytest.mark.asyncio
async def test_lists_both_files_as_written(store):
    async with TestClient(TestServer(_create_app(_make_adapter()))) as cli:
        resp = await cli.get("/api/memory")
        assert resp.status == 200
        assert await resp.json() == {
            "memory": ["Mia has swimming on Wednesdays", "Prefers replies before 9am"],
            "user": ["Lives in Remuera", "Doesn't eat pork"],
        }


@pytest.mark.asyncio
async def test_empty_store(monkeypatch):
    class Empty:
        memory_entries, user_entries = [], []
    monkeypatch.setattr(M, "load_on_disk_store", lambda: Empty())
    async with TestClient(TestServer(_create_app(_make_adapter()))) as cli:
        resp = await cli.get("/api/memory")
        assert await resp.json() == {"memory": [], "user": []}


@pytest.mark.asyncio
async def test_requires_api_key(store):
    async with TestClient(TestServer(_create_app(_make_adapter("sk-secret")))) as cli:
        assert (await cli.get("/api/memory")).status == 401
        assert (await cli.get("/api/memory", headers={"Authorization": "Bearer wrong"})).status == 401
        ok = await cli.get("/api/memory", headers={"Authorization": "Bearer sk-secret"})
        assert ok.status == 200
