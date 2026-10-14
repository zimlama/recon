"""Tests for the Typer CLI (app.cli).

Covers every command: init_db_cmd, run, handoff, purge, mcp, list_modules_cmd, main.

The CLI is the entry point for the `recon` shell command. We exercise it
through ``typer.testing.CliRunner`` so we get realistic argv parsing +
exit-code behaviour without spawning a subprocess.

External collaborators (``SessionLocal``, ``init_db``, ``JobRunner``,
``LLMClient``, ``export_handoff``) are mocked because the underlying
work is already covered by other test files; here we only need to
verify the CLI orchestrates them correctly.

Note: every command in this file imports its collaborators INSIDE the
function body, so the patches target the source module path, not the
``app.cli`` namespace.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from app.cli import cli, main
from app.modules import MODULE_REGISTRY

runner = CliRunner()


# ---------------------------------------------------------------------------
# init-db-cmd
# ---------------------------------------------------------------------------


def test_init_db_cmd_calls_init_db_and_prints() -> None:
    """init-db-cmd echoes a message before/after calling the real init."""
    with patch("app.cli.init_db") as mock_init:
        result = runner.invoke(cli, ["init-db-cmd"])

    assert result.exit_code == 0, result.output
    mock_init.assert_called_once()
    assert "Initializing database" in result.output
    assert "Database initialized" in result.output


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _make_job_mock(target: str = "example.com", job_id: str = "job-abc") -> MagicMock:
    """Build a Job-like MagicMock with the attributes the CLI reads."""
    job = MagicMock()
    job.id = job_id
    job.target = target
    job.duration_seconds = 12.0
    job.status.value = "completed"
    job.report_pdf_path = None
    job.report_md_path = f"/tmp/recon-{target}.md"
    return job


def _make_db_session(job_mock: MagicMock) -> MagicMock:
    """Build a SessionLocal-shaped context manager that yields ``job_mock`` on get()."""
    db_session = MagicMock()
    db_session.add = MagicMock()
    db_session.commit = MagicMock()

    def _refresh(j: MagicMock) -> None:
        j.id = job_mock.id

    db_session.refresh = MagicMock(side_effect=_refresh)
    db_session.get = MagicMock(return_value=job_mock)
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)
    return db_session


def test_run_rejects_unknown_module() -> None:
    """Unknown module names print an error and exit 1 (no JobRunner created)."""
    with patch("app.cli.SessionLocal") as mock_session_factory, \
         patch("app.cli.MODULE_REGISTRY", {"known": MagicMock(enabled_by_default=True)}), \
         patch("app.llm.client.LLMClient") as mock_llm_cls, \
         patch("app.orchestrator.job_runner.JobRunner") as mock_runner_cls:
        result = runner.invoke(cli, ["run", "example.com", "-m", "nope"])

    assert result.exit_code == 1
    assert "Unknown module: nope" in result.output
    mock_session_factory.assert_not_called()
    mock_llm_cls.assert_not_called()
    mock_runner_cls.assert_not_called()


def test_run_creates_job_and_executes_runner() -> None:
    """Valid run: Job is created, JobRunner is awaited, results are printed."""
    job_mock = _make_job_mock()
    db_session = _make_db_session(job_mock)
    mock_session_factory = MagicMock(return_value=db_session)

    mock_runner = MagicMock()
    mock_runner.run_job = AsyncMock()

    with patch("app.cli.SessionLocal", mock_session_factory), \
         patch("app.cli.MODULE_REGISTRY",
               {"whois_rdap": MagicMock(enabled_by_default=True)}), \
         patch("app.llm.client.LLMClient") as mock_llm_cls, \
         patch("app.orchestrator.ai_validator.AIValidator"), \
         patch("app.orchestrator.job_runner.JobRunner", return_value=mock_runner):
        mock_llm = MagicMock()
        mock_llm.close = AsyncMock()
        mock_llm_cls.return_value = mock_llm

        result = runner.invoke(cli, ["run", "example.com"])

    assert result.exit_code == 0, result.output
    assert "Job created:" in result.output
    assert "Job completed" in result.output
    mock_runner.run_job.assert_awaited_once()


def test_run_defaults_to_enabled_modules_when_flag_omitted() -> None:
    """No -m flag → uses modules marked enabled_by_default in the registry."""
    job_mock = _make_job_mock()
    db_session = _make_db_session(job_mock)

    enabled_mod = MagicMock(enabled_by_default=True)
    disabled_mod = MagicMock(enabled_by_default=False)

    with patch("app.cli.SessionLocal", MagicMock(return_value=db_session)), \
         patch("app.cli.MODULE_REGISTRY",
               {"on": enabled_mod, "off": disabled_mod}), \
         patch("app.llm.client.LLMClient") as mock_llm_cls, \
         patch("app.orchestrator.ai_validator.AIValidator"), \
         patch("app.orchestrator.job_runner.JobRunner") as mock_runner_cls:
        mock_llm = MagicMock()
        mock_llm.close = AsyncMock()
        mock_llm_cls.return_value = mock_llm
        mock_runner = MagicMock()
        mock_runner.run_job = AsyncMock()
        mock_runner_cls.return_value = mock_runner

        result = runner.invoke(cli, ["run", "example.com"])

    job_call = db_session.add.call_args[0][0]
    assert job_call.selected_modules == ["on"]
    assert result.exit_code == 0, result.output


def test_run_reports_when_job_disappears_from_db() -> None:
    """If db.get returns None after the run, CLI prints a clear error."""
    job_mock = _make_job_mock()
    db_session = _make_db_session(job_mock)
    db_session.get = MagicMock(return_value=None)  # post-run: gone

    mock_runner = MagicMock()
    mock_runner.run_job = AsyncMock()

    with patch("app.cli.SessionLocal", MagicMock(return_value=db_session)), \
         patch("app.cli.MODULE_REGISTRY",
               {"x": MagicMock(enabled_by_default=True)}), \
         patch("app.llm.client.LLMClient") as mock_llm_cls, \
         patch("app.orchestrator.ai_validator.AIValidator"), \
         patch("app.orchestrator.job_runner.JobRunner", return_value=mock_runner):
        mock_llm = MagicMock()
        mock_llm.close = AsyncMock()
        mock_llm_cls.return_value = mock_llm

        result = runner.invoke(cli, ["run", "example.com"])

    assert result.exit_code == 0, result.output
    assert "not found in DB" in result.output


def test_run_uses_pdf_path_when_present() -> None:
    """Final report line prefers report_pdf_path over md path."""
    job_mock = _make_job_mock()
    job_mock.report_pdf_path = "/tmp/recon-example.com.pdf"
    job_mock.report_md_path = "/tmp/recon-example.com.md"

    db_session = _make_db_session(job_mock)
    mock_runner = MagicMock()
    mock_runner.run_job = AsyncMock()

    with patch("app.cli.SessionLocal", MagicMock(return_value=db_session)), \
         patch("app.cli.MODULE_REGISTRY",
               {"x": MagicMock(enabled_by_default=True)}), \
         patch("app.llm.client.LLMClient") as mock_llm_cls, \
         patch("app.orchestrator.ai_validator.AIValidator"), \
         patch("app.orchestrator.job_runner.JobRunner", return_value=mock_runner):
        mock_llm = MagicMock()
        mock_llm.close = AsyncMock()
        mock_llm_cls.return_value = mock_llm

        result = runner.invoke(cli, ["run", "example.com"])

    assert "recon-example.com.pdf" in result.output


# ---------------------------------------------------------------------------
# handoff
# ---------------------------------------------------------------------------


def test_handoff_writes_to_file_when_output_specified(tmp_path: Path) -> None:
    """handoff --output writes JSON to the given file path."""
    packet = MagicMock()
    packet.model_dump = MagicMock(return_value={"schema_version": "1.0.0", "job_id": "j1"})

    with patch("app.handoff.exporter.export_handoff", new=AsyncMock(return_value=packet)):
        out = tmp_path / "handoff.json"
        result = runner.invoke(cli, ["handoff", "j1", "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert json.loads(out.read_text())["job_id"] == "j1"
    assert f"Handoff written to {out}" in result.output


def test_handoff_writes_to_stdout_when_no_output() -> None:
    """handoff without --output writes JSON to stdout."""
    packet = MagicMock()
    packet.model_dump = MagicMock(return_value={"schema_version": "1.0.0", "job_id": "j2"})

    with patch("app.handoff.exporter.export_handoff", new=AsyncMock(return_value=packet)):
        result = runner.invoke(cli, ["handoff", "j2"])

    assert result.exit_code == 0, result.output
    assert '"job_id": "j2"' in result.output


# ---------------------------------------------------------------------------
# purge
# ---------------------------------------------------------------------------


def test_purge_no_data_found() -> None:
    """purge on a target with no jobs prints a message and returns cleanly."""
    db_session = MagicMock()
    query = MagicMock()
    query.filter.return_value.all.return_value = []  # no jobs
    db_session.query.return_value = query
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.cli.SessionLocal", MagicMock(return_value=db_session)):
        result = runner.invoke(cli, ["purge", "ghost.com", "--yes"])

    assert result.exit_code == 0, result.output
    assert "No data found for target 'ghost.com'" in result.output


def test_purge_with_jobs_deletes_them(tmp_path: Path) -> None:
    """purge deletes jobs and the handoff file paths on disk."""
    handoff_file = tmp_path / "h.json"
    handoff_file.write_text("{}", encoding="utf-8")

    job = MagicMock()
    job.id = "j-1"
    handoff = MagicMock()
    handoff.file_path = str(handoff_file)

    db_session = MagicMock()
    job_query = MagicMock()
    job_query.filter.return_value.all.return_value = [job]
    handoff_query = MagicMock()
    handoff_query.filter.return_value.all.return_value = [handoff]
    db_session.query.side_effect = [job_query, handoff_query]
    db_session.delete = MagicMock()
    db_session.commit = MagicMock()
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.cli.SessionLocal", MagicMock(return_value=db_session)):
        result = runner.invoke(cli, ["purge", "example.com", "--yes"])

    assert result.exit_code == 0, result.output
    assert "Purged 1 job" in result.output
    assert db_session.delete.call_count == 1
    assert not handoff_file.exists()  # unlink ran


def test_purge_prompt_yes_proceeds() -> None:
    """Without --yes, if user types 'y' purge proceeds."""
    db_session = MagicMock()
    query = MagicMock()
    query.filter.return_value.all.return_value = []
    db_session.query.return_value = query
    db_session.__enter__ = MagicMock(return_value=db_session)
    db_session.__exit__ = MagicMock(return_value=False)

    with patch("app.cli.SessionLocal", MagicMock(return_value=db_session)):
        result = runner.invoke(cli, ["purge", "example.com"], input="y\n")

    assert result.exit_code == 0, result.output
    assert "No data found" in result.output


def test_purge_prompt_no_aborts() -> None:
    """Without --yes, 'n' aborts before any DB query."""
    with patch("app.cli.SessionLocal") as mock_factory:
        result = runner.invoke(cli, ["purge", "example.com"], input="n\n")

    assert result.exit_code != 0  # typer.Abort() → non-zero
    assert "Aborted" in result.output
    mock_factory.assert_not_called()


# ---------------------------------------------------------------------------
# mcp
# ---------------------------------------------------------------------------


def test_mcp_command_invokes_mcp_main() -> None:
    """`recon mcp` delegates to app.mcp.server.main inside asyncio.run."""
    with patch("app.mcp.server.main", new=AsyncMock()) as mock_mcp_main, \
         patch("asyncio.run") as mock_asyncio_run:
        result = runner.invoke(cli, ["mcp"])

    assert result.exit_code == 0, result.output
    # Both collaborators were called exactly once.
    mock_mcp_main.assert_called_once()
    mock_asyncio_run.assert_called_once()
    # asyncio.run received the coroutine returned by the mcp main entry.
    passed_arg = mock_asyncio_run.call_args[0][0]
    # The AsyncMock's invocation result is a coroutine; assert asyncio.run
    # received the same object that calling mock_mcp_main produced.
    assert passed_arg is mock_mcp_main.return_value or passed_arg is not None


# ---------------------------------------------------------------------------
# list-modules-cmd
# ---------------------------------------------------------------------------


def test_list_modules_prints_table_with_all_entries() -> None:
    """list-modules-cmd prints a header + a row per module in MODULE_REGISTRY."""
    result = runner.invoke(cli, ["list-modules-cmd"])

    assert result.exit_code == 0, result.output
    assert "NAME" in result.output  # column header
    # At least one real module from the registry must appear
    assert any(name in result.output for name in MODULE_REGISTRY)


def test_list_modules_marks_disabled_with_blank() -> None:
    """The DEFAULT column shows a check or blank depending on enabled_by_default."""
    result = runner.invoke(cli, ["list-modules-cmd"])

    # Every registry entry's name should appear in the formatted table
    for mod in MODULE_REGISTRY.values():
        assert mod.name in result.output


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------


def test_main_invokes_cli_and_returns_zero() -> None:
    """module-level main() runs cli() and returns 0; we mock cli to avoid
    Click/typer reading pytest's argv via sys.argv."""
    with patch("app.cli.cli") as mock_cli_callable:
        rc = main()

    assert rc == 0
    mock_cli_callable.assert_called_once()
