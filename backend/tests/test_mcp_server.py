"""Tests for the MCP stdio server (app.mcp.server).

Focused coverage for the security hardening of tool error responses:
the MCP protocol must never leak raw exception text (which can carry SQL
fragments, file paths, secrets, stack frames) back to the client. Full
tracebacks should go to the server-side logger only.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest


class _ExplodingTool:
    """Stand-in for a registered MCP tool that always raises."""

    async def __call__(self, *args: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: D401
        raise RuntimeError("SECRET INTERNAL DETAIL: SELECT * FROM users")


@pytest.mark.asyncio
async def test_tools_call_returns_generic_error_on_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Tool exceptions must surface a generic error, never the raw text."""
    from app.mcp.server import ReconMCPServer

    server = ReconMCPServer()
    server.tools["boom"] = _ExplodingTool()

    request = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {"name": "boom", "arguments": {}},
    }

    with caplog.at_level(logging.ERROR, logger="app.mcp.server"):
        response = await server.handle_request(request)

    assert "error" in response
    err = response["error"]
    assert err["code"] == -32603
    # Generic, opaque: no exception text leaked
    assert "SECRET INTERNAL DETAIL" not in err["message"]
    assert "SELECT * FROM users" not in err["message"]
    assert err["message"] == "Internal error (see server logs)"
    assert err["tool"] == "boom"
    # Full traceback landed in server-side logs
    assert any("boom" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_tools_call_unknown_tool_returns_method_not_found() -> None:
    """Unknown tool names return the standard JSON-RPC method-not-found."""
    from app.mcp.server import ReconMCPServer

    server = ReconMCPServer()
    response = await server.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "does_not_exist", "arguments": {}},
    })
    assert response["error"]["code"] == -32601
    assert "does_not_exist" in response["error"]["message"]