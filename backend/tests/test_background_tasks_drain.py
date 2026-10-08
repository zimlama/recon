"""Tests for graceful shutdown of in-flight background job tasks.

Audit finding R4-H3: POST /api/v1/jobs used to use FastAPI's
BackgroundTasks, which drains on response but NOT on process shutdown.
SIGTERM during a long-running job killed the asyncio.gather mid-flight,
leaving the Job row stuck in RUNNING.

The fix: \`create_job\` wraps the work in an asyncio.Task tracked in a
module-level set. The lifespan manager awaits that set with a 30s
cap on shutdown.

This test verifies the drain machinery directly: register two slow
asyncio.Tasks via the module-level set, call the drain helper, assert
both complete.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.routes import jobs as jobs_routes


def _clear_tracked() -> None:
    jobs_routes.get_background_job_tasks().clear()


@pytest.mark.asyncio
async def test_drain_background_job_tasks_async_completes_in_flight() -> None:
    """Drain awaits tracked background tasks with a 30s cap."""
    _clear_tracked()

    async def _slow_job(name: str) -> str:
        await asyncio.sleep(0.05)
        return name

    tasks = [
        asyncio.create_task(_slow_job(f"job_{i}")) for i in range(3)
    ]
    for t in tasks:
        jobs_routes.get_background_job_tasks().add(t)
        t.add_done_callback(jobs_routes.get_background_job_tasks().discard)

    # Drain — both should complete within the 30s default.
    done, pending = await jobs_routes.drain_background_job_tasks_async(
        timeout=5.0
    )
    assert done == 3
    assert pending == 0
    assert jobs_routes.get_background_job_tasks() == set()


@pytest.mark.asyncio
async def test_drain_does_not_hang_on_unresponsive_task() -> None:
    """Drain returns at timeout when a task refuses to complete.

    A truly stuck task shouldn't block shutdown forever — we cap the
    drain at 30s and let the operator inspect remaining work via logs.
    """
    _clear_tracked()

    cancelled: list[bool] = []

    async def _stuck_job() -> None:
        try:
            await asyncio.sleep(60)  # way past drain timeout
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    task = asyncio.create_task(_stuck_job())
    jobs_routes.get_background_job_tasks().add(task)
    task.add_done_callback(jobs_routes.get_background_job_tasks().discard)

    # Drain with a 0.1s timeout — task is forced to remain pending.
    done, pending = await jobs_routes.drain_background_job_tasks_async(
        timeout=0.1
    )
    assert done == 0
    assert pending == 1

    # Cancel the stuck task so the test cleans up.
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert cancelled == [True]


@pytest.mark.asyncio
async def test_drain_empty_set_is_noop() -> None:
    """Drain must be a fast no-op when no tasks are tracked."""
    _clear_tracked()
    done, pending = await jobs_routes.drain_background_job_tasks_async(
        timeout=0.0
    )
    assert done == 0
    assert pending == 0
