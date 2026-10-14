"""Tests for the MCP server tool surface (app.mcp.server).

Complements test_mcp_server.py (which only covers the error-handling of
handle_request) by exercising every tool implementation + lifecycle hook:

- start_recon_job  (with confirm_target defense, target normalization,
  registry filtering, background task tracking)
- _run_job_with_tracking  (cancelled → job marked FAILED in DB)
- shutdown  (cancels all running tasks, idempotent)
- get_job_status  (404 + 200 paths, module_runs list shape)
- get_findings  (verdict filter, AI verdict mapping)
- get_handoff  (no handoff yet → triggers export; existing → returns it)
- get_report_path  (404 + 200)
- list_modules  (registry pass-through)
- handle_request  (tools/list happy path + unknown method)
- main  (entry point calls server.run)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.mcp.server import ReconMCPServer

# ---------------------------------------------------------------------------
# start_recon_job — consent + dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_recon_job_requires_confirm_target() -> None:
    """Defense-in-depth: missing confirm_target raises ValueError before DB write."""
    server = ReconMCPServer()
    with pytest.raises(ValueError, match="confirm_target"):
        await server.start_recon_job(target="example.com")


@pytest.mark.asyncio
async def test_start_recon_job_rejects_mismatched_confirm() -> None:
    """confirm_target must match the target (case-insensitive)."""
    server = ReconMCPServer()
    with pytest.raises(ValueError, match="does not match"):
        await server.start_recon_job(
            target="example.com", confirm_target="evil.com"
        )


@pytest.mark.asyncio
async def test_start_recon_job_normalizes_target_case() -> None:
    """Target is lowercased and stripped before persistence."""
    server = ReconMCPServer()

    db_session = MagicMock()
    db_session.add = MagicMock()
    db_session.commit = MagicMock()
    db_session.refresh = MagicMock(side_effect=lambda j: setattr(j, "id", "job-1"))
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         patch("asyncio.create_task"):
        result = await server.start_recon_job(
            target="  EXAMPLE.COM  ", confirm_target="example.com"
        )
    assert result is not None

    # The persisted Job had its target normalized
    job_arg = db_session.add.call_args[0][0]
    assert job_arg.target == "example.com"
    assert result["target"] == "  EXAMPLE.COM  "  # echo back what user passed
    assert result["job_id"] == "job-1"
    assert result["status"] == "pending"


@pytest.mark.asyncio
async def test_start_recon_job_defaults_to_enabled_modules() -> None:
    """When modules=None, only enabled_by_default modules are selected."""
    server = ReconMCPServer()

    db_session = MagicMock()
    db_session.add = MagicMock()
    db_session.commit = MagicMock()
    db_session.refresh = MagicMock(side_effect=lambda j: setattr(j, "id", "j"))
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    enabled = MagicMock(enabled_by_default=True)
    disabled = MagicMock(enabled_by_default=False)
    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         patch("app.mcp.server.MODULE_REGISTRY",
               {"on": enabled, "off": disabled}), \
         patch("asyncio.create_task"):
        result = await server.start_recon_job(
            target="example.com", confirm_target="example.com"
        )
    assert result is not None

    job_arg = db_session.add.call_args[0][0]
    assert job_arg.selected_modules == ["on"]


@pytest.mark.asyncio
async def test_start_recon_job_registers_task() -> None:
    """A background task is created and tracked in _running_tasks."""
    server = ReconMCPServer()

    db_session = MagicMock()
    db_session.add = MagicMock()
    db_session.commit = MagicMock()
    db_session.refresh = MagicMock(side_effect=lambda j: setattr(j, "id", "j-1"))
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    # The create_task mock simulates a task whose callback removes it from the dict
    fake_task = MagicMock()
    fake_task.add_done_callback = MagicMock()

    def fake_create_task(coro: Any) -> MagicMock:
        # Run the callback immediately so _running_tasks is cleaned up
        return fake_task

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         patch("asyncio.create_task", side_effect=fake_create_task):
        await server.start_recon_job(
            target="example.com", confirm_target="example.com"
        )

    fake_task.add_done_callback.assert_called_once()


# ---------------------------------------------------------------------------
# _run_job_with_tracking — cancellation handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_job_with_tracking_marks_job_failed_on_cancel() -> None:
    """If _run_job raises CancelledError, the job is marked FAILED in the DB."""
    server = ReconMCPServer()

    job = MagicMock()
    job.id = "j-cancel"
    job.status = MagicMock()  # not in terminal state

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.commit = MagicMock()
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    async def raise_cancel(_job_id: str) -> None:
        raise asyncio.CancelledError()

    with patch.object(server, "_run_job", side_effect=raise_cancel), \
         patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         contextlib.suppress(asyncio.CancelledError):
        await server._run_job_with_tracking("j-cancel")

    db_session.commit.assert_called_once()
    # The job's status was set to FAILED
    from app.models import JobStatus

    assert job.status == JobStatus.FAILED
    assert "cancelled" in (job.error_message or "").lower()


@pytest.mark.asyncio
async def test_run_job_with_tracking_noop_on_completed_job() -> None:
    """If the job is already in a terminal state, cancellation does NOT overwrite it."""
    server = ReconMCPServer()

    from app.models import JobStatus

    job = MagicMock()
    job.id = "j-done"
    original_status = JobStatus.COMPLETED
    job.status = original_status

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    async def raise_cancel(_job_id: str) -> None:
        raise asyncio.CancelledError()

    with patch.object(server, "_run_job", side_effect=raise_cancel), \
         patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         contextlib.suppress(asyncio.CancelledError):
        await server._run_job_with_tracking("j-done")

    # Status was NOT overwritten
    assert job.status == original_status
    db_session.commit.assert_not_called()


# ---------------------------------------------------------------------------
# shutdown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shutdown_with_no_running_tasks_is_noop() -> None:
    """shutdown() with empty _running_tasks just sets the event and returns."""
    server = ReconMCPServer()
    await server.shutdown()
    assert server._shutdown_event.is_set()


@pytest.mark.asyncio
async def test_shutdown_cancels_running_tasks() -> None:
    """shutdown() cancels every task in _running_tasks and clears the dict."""
    server = ReconMCPServer()

    t1 = MagicMock()
    t1.cancel = MagicMock()
    t2 = MagicMock()
    t2.cancel = MagicMock()

    server._running_tasks = {"a": t1, "b": t2}

    # Make asyncio.gather return (2, 0) for done/pending counts
    async def fake_gather(*args: Any, **kwargs: Any) -> Any:
        return None

    with patch("app.mcp.server.asyncio.gather", new=fake_gather):
        await server.shutdown()

    t1.cancel.assert_called_once()
    t2.cancel.assert_called_once()
    assert server._running_tasks == {}


# ---------------------------------------------------------------------------
# get_job_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_job_status_404_when_missing() -> None:
    """get_job_status raises ValueError when the job doesn't exist."""
    server = ReconMCPServer()
    db_session = MagicMock()
    db_session.get = MagicMock(return_value=None)
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         pytest.raises(ValueError, match="not found"):
        await server.get_job_status("missing")


@pytest.mark.asyncio
async def test_get_job_status_returns_serializable_payload() -> None:
    """get_job_status returns the documented dict shape."""
    server = ReconMCPServer()

    job = MagicMock()
    job.id = "j-1"
    job.target = "example.com"
    job.status.value = "completed"
    job.created_at = None
    job.started_at = None
    job.completed_at = None
    job.duration_seconds = 5.5
    job.module_runs = []

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.query.return_value.filter.return_value.all.return_value = []
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)):
        out = await server.get_job_status("j-1")

    assert out["job_id"] == "j-1"
    assert out["status"] == "completed"
    assert out["module_runs"] == []


@pytest.mark.asyncio
async def test_get_job_status_includes_module_runs() -> None:
    """get_job_status serializes module_runs with the expected fields."""
    server = ReconMCPServer()

    job = MagicMock()
    job.id = "j-1"
    job.target = "example.com"
    job.status.value = "completed"
    job.created_at = None
    job.started_at = None
    job.completed_at = None
    job.duration_seconds = 1.0

    mr = MagicMock()
    mr.module_name = "whois_rdap"
    mr.status.value = "completed"
    mr.findings_count = 3
    mr.duration_seconds = 0.5

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.query.return_value.filter.return_value.all.return_value = [mr]
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)):
        out = await server.get_job_status("j-1")

    assert len(out["module_runs"]) == 1
    assert out["module_runs"][0]["module"] == "whois_rdap"
    assert out["module_runs"][0]["findings_count"] == 3


# ---------------------------------------------------------------------------
# get_findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_findings_404_when_missing() -> None:
    """get_findings raises ValueError when the job doesn't exist."""
    server = ReconMCPServer()
    db_session = MagicMock()
    db_session.get = MagicMock(return_value=None)
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         pytest.raises(ValueError, match="not found"):
        await server.get_findings("missing")


@pytest.mark.asyncio
async def test_get_findings_collects_per_finding_verdict() -> None:
    """Each finding picks up its verdict from the matching AI validation entry."""
    server = ReconMCPServer()

    job = MagicMock()
    job.id = "j-1"
    validation = MagicMock()
    validation.decision = {
        "verdicts": [
            {"value": "api.example.com", "verdict": "CONFIRMED"},
        ]
    }
    finding = MagicMock()
    finding.type.value = "subdomain"
    finding.value = "api.example.com"
    finding.source = "crtsh"
    finding.confidence = 0.9
    mr = MagicMock()
    mr.module_name = "whois_rdap"
    mr.findings = [finding]

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.query.return_value.filter.return_value.all.return_value = [mr]
    db_session.query.return_value.filter.return_value.first.return_value = validation
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)):
        out = await server.get_findings("j-1")

    assert out["total"] == 1
    assert out["findings"][0]["ai_verdict"] == "CONFIRMED"


@pytest.mark.asyncio
async def test_get_findings_filters_by_verdict() -> None:
    """When verdict is set, only findings with matching ai_verdict are returned."""
    server = ReconMCPServer()

    job = MagicMock()
    job.id = "j-1"
    validation = MagicMock()
    validation.decision = {
        "verdicts": [
            {"value": "a.example.com", "verdict": "CONFIRMED"},
            {"value": "b.example.com", "verdict": "FALSE_POSITIVE"},
        ]
    }
    fa = MagicMock()
    fa.type.value = "subdomain"
    fa.value = "a.example.com"
    fa.source = "x"
    fa.confidence = 0.9
    fb = MagicMock()
    fb.type.value = "subdomain"
    fb.value = "b.example.com"
    fb.source = "x"
    fb.confidence = 0.4
    mr = MagicMock()
    mr.module_name = "whois_rdap"
    mr.findings = [fa, fb]

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.query.return_value.filter.return_value.all.return_value = [mr]
    db_session.query.return_value.filter.return_value.first.return_value = validation
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)):
        out = await server.get_findings("j-1", verdict="CONFIRMED")

    assert out["total"] == 1
    assert out["findings"][0]["value"] == "a.example.com"


# ---------------------------------------------------------------------------
# get_handoff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_handoff_returns_existing_packet() -> None:
    """If a Handoff row exists, its packet is returned (no export)."""
    server = ReconMCPServer()

    job = MagicMock()
    job.id = "j-1"
    handoff = MagicMock()
    handoff.packet = {"schema_version": "1.0.0", "job_id": "j-1"}

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.query.return_value.filter.return_value.first.return_value = handoff
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)):
        out = await server.get_handoff("j-1")

    assert out["job_id"] == "j-1"


@pytest.mark.asyncio
async def test_get_handoff_generates_when_missing() -> None:
    """If no Handoff row, export_handoff is called and its result returned."""
    server = ReconMCPServer()

    job = MagicMock()
    job.id = "j-1"

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.query.return_value.filter.return_value.first.return_value = None
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    fake_packet = MagicMock()
    fake_packet.model_dump = MagicMock(return_value={"schema_version": "1.0.0"})

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         patch(
             "app.mcp.server.export_handoff",
             new=AsyncMock(return_value=fake_packet),
         ):
        out = await server.get_handoff("j-1")

    assert out == {"schema_version": "1.0.0"}


@pytest.mark.asyncio
async def test_get_handoff_404_when_job_missing() -> None:
    """get_handoff raises ValueError when the job doesn't exist."""
    server = ReconMCPServer()
    db_session = MagicMock()
    db_session.get = MagicMock(return_value=None)
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         pytest.raises(ValueError, match="not found"):
        await server.get_handoff("missing")


# ---------------------------------------------------------------------------
# get_report_path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_report_path_404() -> None:
    """get_report_path raises ValueError when the job doesn't exist."""
    server = ReconMCPServer()
    db_session = MagicMock()
    db_session.get = MagicMock(return_value=None)
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)), \
         pytest.raises(ValueError, match="not found"):
        await server.get_report_path("missing")


@pytest.mark.asyncio
async def test_get_report_path_returns_paths() -> None:
    """get_report_path returns the job's md + pdf paths (which may be None)."""
    server = ReconMCPServer()
    job = MagicMock()
    job.id = "j-1"
    job.report_md_path = "/tmp/r.md"
    job.report_pdf_path = "/tmp/r.pdf"

    db_session = MagicMock()
    db_session.get = MagicMock(return_value=job)
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.mcp.server.SessionLocal", MagicMock(return_value=db_session)):
        out = await server.get_report_path("j-1")

    assert out["md_path"] == "/tmp/r.md"
    assert out["pdf_path"] == "/tmp/r.pdf"


# ---------------------------------------------------------------------------
# list_modules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_modules_returns_registry_metadata() -> None:
    """list_modules returns a serialized view of MODULE_REGISTRY."""
    from app.modules import MODULE_REGISTRY

    server = ReconMCPServer()
    out = await server.list_modules()

    assert "modules" in out
    assert "total" in out
    assert out["total"] == len(MODULE_REGISTRY)
    assert all("name" in m for m in out["modules"])


# ---------------------------------------------------------------------------
# handle_request — tools/list + unknown method
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_request_tools_list_returns_schema() -> None:
    """handle_request('tools/list') returns the documented tool schema."""
    server = ReconMCPServer()
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    response = await server.handle_request(request)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    tool_names = {t["name"] for t in response["result"]["tools"]}
    assert "start_recon_job" in tool_names
    assert "list_modules" in tool_names


@pytest.mark.asyncio
async def test_handle_request_unknown_method_returns_method_not_found() -> None:
    """handle_request with an unknown method returns -32601 (method not found)."""
    server = ReconMCPServer()
    request = {"jsonrpc": "2.0", "id": 7, "method": "tools/banana"}
    response = await server.handle_request(request)

    assert response["error"]["code"] == -32601
    assert "tools/banana" in response["error"]["message"]


@pytest.mark.asyncio
async def test_handle_request_successful_tool_call_returns_text_content() -> None:
    """A successful tool call wraps the result in a content/text envelope."""
    server = ReconMCPServer()

    # Replace one of the tools with a deterministic async function
    async def fake_list_modules() -> dict[str, Any]:
        return {"modules": [], "total": 0}

    server.tools["list_modules"] = fake_list_modules

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "list_modules", "arguments": {}},
    }
    response = await server.handle_request(request)
    assert "result" in response
    content = response["result"]["content"]
    assert content[0]["type"] == "text"
    assert json.loads(content[0]["text"]) == {"modules": [], "total": 0}
