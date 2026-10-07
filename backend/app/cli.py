"""Typer CLI for zimlama/recon backend.

Commands:
- recon init-db            Initialize the database
- recon run <target>        Run a recon from CLI
- recon handoff <job_id>    Export a handoff packet
- recon purge <target>      Delete all data for a target
- recon mcp                 Start MCP stdio server
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer

from app.config import get_settings
from app.database import SessionLocal, init_db
from app.models import Finding, Handoff, Job, ModuleRun
from app.modules import MODULE_REGISTRY

cli = typer.Typer(
    name="recon",
    help="zimlama/recon — Phase 1 ethical hacking reconnaissance framework",
    no_args_is_help=True,
    add_completion=False,
)


@cli.command()
def init_db_cmd() -> None:
    """Initialize the database (create tables)."""
    typer.echo("Initializing database...")
    init_db()
    typer.echo("✅ Database initialized")


@cli.command()
def run(
    target: str = typer.Argument(..., help="Target domain to recon"),
    modules: list[str] | None = typer.Option(None, "--module", "-m", help="Module names to run (repeatable)"),
) -> None:
    """Run a recon from the CLI (without UI)."""
    from app.llm.client import LLMClient
    from app.orchestrator.ai_validator import AIValidator
    from app.orchestrator.job_runner import JobRunner

    if modules is None:
        modules = [m for m, mod in MODULE_REGISTRY.items() if mod.enabled_by_default]

    # Validate modules
    for m in modules:
        if m not in MODULE_REGISTRY:
            typer.echo(f"❌ Unknown module: {m}. Available: {list(MODULE_REGISTRY)}")
            raise typer.Exit(1)

    # Create job
    from datetime import datetime
from app.models import _now
    with SessionLocal() as db:
        job = Job(
            target=target,
            target_type="domain",
            selected_modules=modules,
            user_consent=True,
            typed_confirmation=target,
            consent_modal_version="cli-v1",
            consent_timestamp=_now(),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        job_id = job.id
        typer.echo(f"✅ Job created: {job_id}")

    # Run
    async def _run() -> None:
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

    asyncio.run(_run())

    # Print results
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job:
            typer.echo(f"\n✅ Job completed in {job.duration_seconds:.0f}s")
            typer.echo(f"   Status: {job.status.value}")
            typer.echo(f"   Report: {job.report_pdf_path or job.report_md_path or 'not generated'}")


@cli.command()
def handoff(
    job_id: str = typer.Argument(..., help="Job ID to export handoff for"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path (default: stdout)"),
) -> None:
    """Export a handoff packet for a job."""
    from app.handoff.exporter import export_handoff

    async def _export() -> None:
        packet = await export_handoff(job_id)
        return packet

    packet = asyncio.run(_export())
    json_data = json.dumps(packet.model_dump(mode="json"), indent=2, ensure_ascii=False)

    if output:
        output.write_text(json_data, encoding="utf-8")
        typer.echo(f"✅ Handoff written to {output}")
    else:
        typer.echo(json_data)


@cli.command()
def purge(
    target: str = typer.Argument(..., help="Target domain to purge (deletes ALL data)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Delete all data for a target (jobs, findings, handoffs, audit logs)."""
    if not yes:
        confirm = typer.confirm(f"Delete ALL data for target '{target}'? This is irreversible.")
        if not confirm:
            typer.echo("Aborted.")
            raise typer.Abort()

    with SessionLocal() as db:
        # Find all jobs for target
        jobs = db.query(Job).filter(Job.target == target).all()
        if not jobs:
            typer.echo(f"No data found for target '{target}'")
            return

        job_count = len(jobs)
        # Delete handoff files
        handoffs = db.query(Handoff).filter(Handoff.job_id.in_([j.id for j in jobs])).all()
        for h in handoffs:
            if h.file_path and Path(h.file_path).exists():
                Path(h.file_path).unlink()

        # Cascade delete jobs
        for j in jobs:
            db.delete(j)
        db.commit()

    typer.echo(f"✅ Purged {job_count} job(s) for target '{target}'")


@cli.command()
def mcp() -> None:
    """Start the MCP stdio server."""
    from app.mcp.server import main as mcp_main

    asyncio.run(mcp_main())


@cli.command()
def list_modules_cmd() -> None:
    """List all available recon modules."""
    typer.echo(f"{'NAME':<25} {'TIER':<10} {'DEFAULT':<8} DESCRIPTION")
    typer.echo("─" * 100)
    for m in MODULE_REGISTRY.values():
        typer.echo(
            f"{m.name:<25} {m.tier.value:<10} {'✓' if m.enabled_by_default else ' ':<8} {m.description[:55]}"
        )


def main() -> None:
    """CLI entry point (called by `recon` command)."""
    cli()


if __name__ == "__main__":
    sys.exit(main() or 0)
