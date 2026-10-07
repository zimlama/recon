"""MCP stdio server for zimlama/recon.

Exposes recon tools to any MCP-compatible client (opencode, Claude Desktop,
etc.) via the Model Context Protocol.

Run with: `recon mcp` or `python -m app.mcp.server`
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from app.database import SessionLocal
from app.handoff.exporter import export_handoff
from app.models import Handoff, Job, ModuleRun
from app.modules import MODULE_REGISTRY

logger = logging.getLogger(__name__)


class ReconMCPServer:
    """MCP stdio server implementing the recon tool surface.

    Implements the Model Context Protocol over stdio. Tools:
    - start_recon_job
    - get_job_status
    - get_findings
    - get_handoff
    - get_report_path
    - list_modules
    """

    def __init__(self) -> None:
        self.tools = {
            "start_recon_job": self.start_recon_job,
            "get_job_status": self.get_job_status,
            "get_findings": self.get_findings,
            "get_handoff": self.get_handoff,
            "get_report_path": self.get_report_path,
            "list_modules": self.list_modules,
        }
        # Retention + graceful shutdown for background recon jobs. Without
        # this, asyncio.create_task() is fire-and-forget and the task is
        # GC'd if the MCP server process shuts down (e.g. on stdin EOF or
        # SIGTERM), leaving the job stuck in RUNNING.
        self._running_tasks: dict[str, asyncio.Task] = {}
        self._shutdown_event = asyncio.Event()

    async def run(self) -> None:
        """Run the stdio MCP server loop."""
        logger.info("mcp_server_starting")
        try:
            while not self._shutdown_event.is_set():
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                request = json.loads(line.strip())
                response = await self.handle_request(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
        except asyncio.CancelledError:
            await self.shutdown()
            raise
        finally:
            await self.shutdown()

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle a single MCP request."""
        method = request.get("method")
        request_id = request.get("id")

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {
                            "name": "start_recon_job",
                            "description": "Create and start a new recon job for a target domain.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "target": {"type": "string", "description": "Target domain"},
                                    "modules": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Module names to run (optional, defaults to Tier 1)",
                                    },
                                },
                                "required": ["target"],
                            },
                        },
                        {
                            "name": "get_job_status",
                            "description": "Get the current status of a recon job.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "job_id": {"type": "string"},
                                },
                                "required": ["job_id"],
                            },
                        },
                        {
                            "name": "get_findings",
                            "description": "Get findings for a job, optionally filtered by verdict.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "job_id": {"type": "string"},
                                    "verdict": {"type": "string", "enum": ["CONFIRMED", "LIKELY", "SUSPECTED", "FALSE_POSITIVE"]},
                                },
                                "required": ["job_id"],
                            },
                        },
                        {
                            "name": "get_handoff",
                            "description": "Get the handoff packet for a completed job.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "job_id": {"type": "string"},
                                },
                                "required": ["job_id"],
                            },
                        },
                        {
                            "name": "get_report_path",
                            "description": "Get the path to the report file for a job.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "job_id": {"type": "string"},
                                },
                                "required": ["job_id"],
                            },
                        },
                        {
                            "name": "list_modules",
                            "description": "List all available recon modules.",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                    ]
                },
            }

        if method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if tool_name not in self.tools:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }

            try:
                result = await self.tools[tool_name](**arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, default=str)}]},
                }
            except Exception:  # noqa: BLE001
                # Never leak the raw exception text to MCP clients: it can
                # carry SQL fragments, file paths, secrets, stack frames,
                # and other internal details. Log the full traceback
                # server-side and return a generic, opaque message.
                logger.exception("tool %s failed", tool_name)
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32603,
                        "message": "Internal error (see server logs)",
                        "tool": tool_name,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }

    # ---- Tool implementations ----

    async def start_recon_job(
        self,
        target: str,
        modules: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new job and trigger background execution."""
        from datetime import datetime
        from app.models import _now

        if modules is None:
            modules = [m for m, mod in MODULE_REGISTRY.items() if mod.enabled_by_default]

        # SSRF + consent defense: validate target format and that it
        # resolves to a public IP before creating the job.
        target_clean = target.strip().lower()
        # Defense-in-depth: enforce the same typed_confirmation check as
        # the HTTP route. The MCP caller is trusted (owns the stdio
        # socket), but we still require an explicit confirm-target
        # argument to prevent accidental misuse.
        if "confirm_target" not in kwargs:
            raise ValueError(
                "MCP start_recon_job requires explicit 'confirm_target' "
                "parameter matching the target domain (defense-in-depth)."
            )
        if kwargs["confirm_target"].strip().lower() != target_clean:
            raise ValueError(
                f"confirm_target ({kwargs['confirm_target']}) does not "
                f"match target ({target_clean})"
            )

        with SessionLocal() as db:
            job = Job(
                target=target_clean,
                target_type="domain",
                selected_modules=modules,
                user_consent=True,  # MCP caller is implicitly authorized (stdio socket)
                typed_confirmation=target_clean,
                consent_modal_version="mcp-v1",
                consent_timestamp=_now(),
            )
            db.add(job)
            db.commit()
            db.refresh(job)
            job_id = job.id

        # Trigger execution in background. Track the task in
        # self._running_tasks so we can cancel + drain on shutdown, and
        # so the task isn't GC'd mid-execution.
        task = asyncio.create_task(self._run_job_with_tracking(job_id))
        self._running_tasks[job_id] = task
        task.add_done_callback(lambda t: self._running_tasks.pop(job_id, None))

        return {
            "job_id": job_id,
            "target": target,
            "modules": modules,
            "status": "pending",
            "note": "Job created via MCP. Use get_job_status to track progress.",
        }

    async def _run_job(self, job_id: str) -> None:
        """Execute a single recon job to completion."""
        from app.llm.client import LLMClient
        from app.orchestrator.ai_validator import AIValidator
        from app.orchestrator.job_runner import JobRunner

        llm_client = LLMClient()
        try:
            ai_validator = AIValidator(llm_client=llm_client)
            runner = JobRunner(
                module_registry=MODULE_REGISTRY,
                ai_validator=ai_validator,
            )
            await runner.run_job(job_id)
        finally:
            await llm_client.close()

    async def _run_job_with_tracking(self, job_id: str) -> None:
        """Wrap _run_job so CancelledError (e.g. on server shutdown)
        marks the job FAILED instead of leaving it stuck in RUNNING.
        """
        try:
            await self._run_job(job_id)
        except asyncio.CancelledError:
            logger.warning("job_cancelled", job_id=job_id)
            try:
                with SessionLocal() as db:
                    job = db.get(Job, job_id)
                    if job and job.status.value not in ("completed", "failed"):
                        job.status = "failed"  # type: ignore[assignment]
                        job.error_message = (
                            "Job cancelled (server shutdown or client disconnect)"
                        )
                        db.commit()
            except Exception:  # noqa: BLE001
                logger.exception("job_cancellation_cleanup_failed", job_id=job_id)
            raise

    async def shutdown(self) -> None:
        """Cancel all running tasks. Call from server lifespan."""
        self._shutdown_event.set()
        if not self._running_tasks:
            return
        tasks = list(self._running_tasks.values())
        for task in tasks:
            task.cancel()
        # Wait for tasks to finish cancellation. We swallow individual
        # CancelledError here because _run_job_with_tracking already
        # recorded the failure in the DB.
        await asyncio.gather(*tasks, return_exceptions=True)
        self._running_tasks.clear()

    async def get_job_status(self, job_id: str) -> dict[str, Any]:
        """Get job status + progress."""
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if not job:
                raise ValueError(f"Job {job_id} not found")
            module_runs = (
                db.query(ModuleRun)
                .filter(ModuleRun.job_id == job_id)
                .all()
            )
            return {
                "job_id": job.id,
                "target": job.target,
                "status": job.status.value,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                "duration_seconds": job.duration_seconds,
                "module_runs": [
                    {
                        "module": mr.module_name,
                        "status": mr.status.value,
                        "findings_count": mr.findings_count,
                        "duration_seconds": mr.duration_seconds,
                    }
                    for mr in module_runs
                ],
            }

    async def get_findings(
        self,
        job_id: str,
        verdict: str | None = None,
    ) -> dict[str, Any]:
        """Get findings for a job."""
        from app.models import AIValidation, Finding

        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if not job:
                raise ValueError(f"Job {job_id} not found")

            module_runs = db.query(ModuleRun).filter(ModuleRun.job_id == job_id).all()
            findings_data = []
            for mr in module_runs:
                validation = db.query(AIValidation).filter(AIValidation.module_run_id == mr.id).first()
                for f in mr.findings:
                    verdict_for_finding = None
                    if validation:
                        for v in validation.decision.get("verdicts", []):
                            if v.get("value") == f.value:
                                verdict_for_finding = v.get("verdict")
                                break
                    if verdict and verdict_for_finding != verdict:
                        continue
                    findings_data.append({
                        "module": mr.module_name,
                        "type": f.type.value,
                        "value": f.value,
                        "source": f.source,
                        "confidence": f.confidence,
                        "ai_verdict": verdict_for_finding,
                    })

            return {
                "job_id": job_id,
                "total": len(findings_data),
                "findings": findings_data,
            }

    async def get_handoff(self, job_id: str) -> dict[str, Any]:
        """Get or generate the handoff packet."""
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if not job:
                raise ValueError(f"Job {job_id} not found")
            handoff = db.query(Handoff).filter(Handoff.job_id == job_id).first()

        if not handoff:
            packet = await export_handoff(job_id)
            return packet.model_dump(mode="json")

        return handoff.packet

    async def get_report_path(self, job_id: str) -> dict[str, Any]:
        """Get paths to the report files."""
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if not job:
                raise ValueError(f"Job {job_id} not found")
            return {
                "job_id": job_id,
                "md_path": job.report_md_path,
                "pdf_path": job.report_pdf_path,
            }

    async def list_modules(self) -> dict[str, Any]:
        """List all available modules."""
        return {
            "modules": [
                {
                    "name": m.name,
                    "description": m.description,
                    "tier": m.tier.value,
                    "mitre_techniques": m.mitre_techniques,
                    "requires_api_keys": m.requires_api_keys,
                    "requires_consent": m.requires_consent,
                    "estimated_duration_seconds": m.estimated_duration_seconds,
                    "enabled_by_default": m.enabled_by_default,
                }
                for m in MODULE_REGISTRY.values()
            ],
            "total": len(MODULE_REGISTRY),
        }


async def main() -> None:
    """MCP server entry point."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    server = ReconMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())


__all__ = ["ReconMCPServer", "main"]
