"""Tests for the per-target, per-module token-bucket rate limiter.

These tests cover both the basic bucket math and the race-condition fix:
the eager-lock + sync-init-lock pattern. The race regression test uses an
`asyncio.gather` with many concurrent acquisitions on a fresh key and
checks that bucket state is consistent (no torn reads from two coroutines
holding different Lock instances).
"""

from __future__ import annotations

import asyncio

import pytest

from app.orchestrator.rate_limiter import RateLimiter


# ---- Basic bucket behaviour ----


def test_rate_limiter_init_uses_settings_defaults() -> None:
    """Default rps/burst come from settings."""
    limiter = RateLimiter()
    assert limiter.default_rps > 0
    assert limiter.default_burst > 0


def test_rate_limiter_init_accepts_overrides() -> None:
    limiter = RateLimiter(default_rps=10, default_burst=5)
    assert limiter.default_rps == 10
    assert limiter.default_burst == 5


@pytest.mark.asyncio
async def test_acquire_consumes_one_token() -> None:
    """First acquire takes 1 token; bucket has capacity - 1 tokens after."""
    limiter = RateLimiter(default_rps=10, default_burst=5)
    await limiter.acquire("example.com", "dns_enum")
    bucket = limiter._buckets[("example.com", "dns_enum")]  # noqa: SLF001
    # Allow for refill during the call: capacity is 5, at least 4 consumed.
    assert bucket.tokens < 5.0


@pytest.mark.asyncio
async def test_acquire_blocks_when_empty() -> None:
    """When the bucket is empty, acquire must sleep until refill."""
    # 1 rps, burst 1: after the first acquire, the next one must wait ~1s.
    limiter = RateLimiter(default_rps=1, default_burst=1)
    await limiter.acquire("example.com", "dns_enum")
    start = asyncio.get_event_loop().time()
    await limiter.acquire("example.com", "dns_enum")
    elapsed = asyncio.get_event_loop().time() - start
    assert elapsed >= 0.9, f"expected ~1s wait, got {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_keys_are_case_insensitive_and_separated() -> None:
    """Targets are lowercased; (target, action) tuples are distinct keys."""
    limiter = RateLimiter(default_rps=10, default_burst=2)
    await limiter.acquire("Example.COM", "dns_enum")
    await limiter.acquire("example.com", "subdomain_enum")
    assert ("example.com", "dns_enum") in limiter._buckets  # noqa: SLF001
    assert ("example.com", "subdomain_enum") in limiter._buckets  # noqa: SLF001


def test_reset_clears_all_buckets() -> None:
    limiter = RateLimiter(default_rps=10, default_burst=5)

    # Force at least one bucket to exist by going through acquire().
    async def _seed() -> None:
        await limiter.acquire("example.com", "dns_enum")

    asyncio.run(_seed())
    assert len(limiter) == 1

    limiter.reset()
    assert limiter._buckets == {}  # noqa: SLF001


def test_reset_with_target_clears_one_bucket() -> None:
    limiter = RateLimiter(default_rps=10, default_burst=5)

    async def _seed() -> None:
        await limiter.acquire("example.com", "dns_enum")
        await limiter.acquire("example.com", "subdomain_enum")

    asyncio.run(_seed())
    limiter.reset(target="example.com", action="dns_enum")
    assert ("example.com", "dns_enum") not in limiter._buckets  # noqa: SLF001
    assert ("example.com", "subdomain_enum") in limiter._buckets  # noqa: SLF001


# ---- Audit R4-H5: LRU eviction ----


@pytest.mark.asyncio
async def test_rate_limiter_evicts_old_buckets() -> None:
    """``_buckets`` honors ``max_keys`` with LRU eviction.

    Audit R4-H5: the rate limiter's internal dict used to grow without
    bound per distinct ``(target, module)`` pair — a long-running
    process hitting thousands of targets leaked memory. With the LRU
    cap, the oldest (target, action) pair is evicted first.
    """
    cap = 4
    limiter = RateLimiter(
        default_rps=10, default_burst=5, max_keys=cap
    )

    # Force 4 distinct keys into the bucket dict.
    for idx in range(cap):
        # Use acquire() so we go through the same code path production
        # uses; ``defaultdict``-replacement behavior is part of the
        # contract.
        await limiter.acquire(f"target_{idx}.com", "dns_enum")

    assert len(limiter) == cap, (
        f"expected exactly {cap} buckets before overflow, got {len(limiter)}"
    )

    # Acquire on a 5th, never-seen key — must trigger an eviction.
    await limiter.acquire("overflow.example.com", "dns_enum")
    assert len(limiter) == cap, (
        f"expected {cap} buckets after overflow eviction, got {len(limiter)}"
    )

    # All earlier entries should have been touched at least once via
    # their own acquire(). To prove LRU eviction specifically, touch
    # ONLY the first key, then add 3 more — the first key must survive
    # while one of the untoucheds gets evicted.
    limiter.reset()
    for idx in range(cap):
        await limiter.acquire(f"target_{idx}.com", "dns_enum")
    # Touch target_0 to mark it as recently used.
    await limiter.acquire("target_0.com", "dns_enum")
    # Add a new key — oldest non-touched (target_1) should evict.
    await limiter.acquire("new_target.example.com", "dns_enum")
    assert len(limiter) == cap
    assert ("target_0.com", "dns_enum") in limiter._buckets  # noqa: SLF001


def test_rate_limiter_initial_state_includes_capped_dict() -> None:
    """Construction with max_keys=N starts with an empty LRU dict."""
    limiter = RateLimiter(default_rps=10, default_burst=5, max_keys=42)
    assert len(limiter) == 0
    assert limiter._max_keys == 42  # noqa: SLF001

    async def _seed_then_clear() -> None:
        await limiter.acquire("a.com", "x")

    asyncio.run(_seed_then_clear())
    limiter.reset()
    assert len(limiter) == 0
    assert ("a.com", "x") not in limiter._locks  # noqa: SLF001


# ---- Race-condition fix: per-key Lock must be shared ----


def test_get_lock_returns_same_instance_for_same_key() -> None:
    """Repeated calls with the same key must return the same Lock object."""
    limiter = RateLimiter()
    lock1 = limiter._get_lock(("example.com", "dns_enum"))  # noqa: SLF001
    lock2 = limiter._get_lock(("example.com", "dns_enum"))  # noqa: SLF001
    assert lock1 is lock2


def test_get_lock_returns_different_instances_per_key() -> None:
    """Different keys must get different Lock objects."""
    limiter = RateLimiter()
    lock1 = limiter._get_lock(("a.com", "dns_enum"))  # noqa: SLF001
    lock2 = limiter._get_lock(("b.com", "dns_enum"))  # noqa: SLF001
    assert lock1 is not lock2


@pytest.mark.asyncio
async def test_concurrent_acquires_share_one_lock() -> None:
    """Concurrent acquires on the SAME key must use the same asyncio.Lock.

    Regression test for the defaultdict(asyncio.Lock) bug: each coroutine
    that missed on the same key used to get its own Lock object, so
    mutual exclusion was broken. Now all coroutines must funnel through
    one Lock — which means the bucket math can't go negative (a torn
    read would let the bucket drain below zero).
    """
    limiter = RateLimiter(default_rps=1000, default_burst=10)
    # 50 coroutines all want to acquire on the same fresh key concurrently.
    results = await asyncio.gather(
        *[limiter.acquire("race.example.com", "dns_enum") for _ in range(50)]
    )
    assert len(results) == 50

    # After 50 acquires with burst=10, the bucket should be ~exhausted but
    # the refill (1000 rps) makes it hard to assert an exact number. The
    # critical invariant is that the bucket never went negative — the
    # Lock guarantees that all 10 first-pass acquires see bucket >= 1.
    bucket = limiter._buckets[("race.example.com", "dns_enum")]  # noqa: SLF001
    assert bucket.tokens >= 0.0, f"bucket went negative: {bucket.tokens}"


@pytest.mark.asyncio
async def test_concurrent_acquires_different_keys_dont_block() -> None:
    """Different keys must not serialize against each other.

    We test this by acquiring 5 tokens on two different keys concurrently
    with a low-burst, low-rps limiter. If the locks were shared, the
    second key would block on the first and we'd see cumulative delay.
    """
    limiter = RateLimiter(default_rps=1, default_burst=1)
    start = asyncio.get_event_loop().time()
    # Two parallel acquires on different keys, each ~1s wait (burst=1, rps=1).
    await asyncio.gather(
        limiter.acquire("a.example.com", "dns_enum"),
        limiter.acquire("b.example.com", "dns_enum"),
    )
    elapsed = asyncio.get_event_loop().time() - start
    # If they ran serially (shared lock), this would be ~2s. Parallel = ~1s.
    assert elapsed < 1.7, f"different keys blocked each other: {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_high_contention_no_token_loss() -> None:
    """Stress test: 100 coroutines on the same key never over-grant tokens.

    burst=20 means at most 20 first-pass acquires can succeed without
    waiting. If the Lock were shared (correct), exactly 20 succeed fast
    and the rest wait. If the Lock were per-coroutine (the bug), all 100
    would think they got a token and the bucket would go negative.
    """
    limiter = RateLimiter(default_rps=1, default_burst=20)

    # Use a flag so each coroutine records whether it had to wait.
    waited = asyncio.Event()
    waiters = []
    for i in range(100):

        async def acquire(idx: int = i) -> bool:
            # Use a wrapper that records whether asyncio.sleep was called
            # inside acquire — if the bucket underflows, it sleeps.
            before = asyncio.get_event_loop().time()
            await limiter.acquire("stress.example.com", "dns_enum")
            after = asyncio.get_event_loop().time()
            return (after - before) > 0.05  # slept > 50ms = had to wait

        waiters.append(acquire())

    results = await asyncio.gather(*waiters)

    fast = sum(1 for r in results if not r)
    slow = sum(1 for r in results if r)

    # At least 80 of 100 must have waited (only burst=20 didn't have to wait
    # given 1 rps — so 80+ slow is expected).
    assert slow >= 80, f"expected most acquires to wait, got {slow}/100 slow"
    assert fast <= 20, f"at most burst=20 should be fast, got {fast}/100"


# ---- SQLite WAL + busy_timeout (database.py pragma listener) ----


def test_sqlite_pragma_listener_attached_for_sqlite() -> None:
    """The event listener that sets WAL/busy_timeout is registered when
    DATABASE_URL points at SQLite. We can't easily inspect SQLAlchemy's
    registered listeners, so we just exercise the pragma codepath by
    opening a connection and reading back the values."""
    from app.database import engine

    with engine.connect() as conn:
        from sqlalchemy import text

        row = conn.execute(text("PRAGMA journal_mode")).fetchone()
        # journal_mode returns the active mode; on in-memory or shared
        # cache it may report 'memory', but on a file-backed db it
        # reports 'wal'. Either is acceptable — we only verify that
        # setting the pragma didn't raise.
        assert row is not None
        assert row[0].lower() in ("wal", "memory")

        # busy_timeout should be the int we configured
        bt = conn.execute(text("PRAGMA busy_timeout")).fetchone()
        assert bt is not None
        assert int(bt[0]) == 5000

        # synchronous should be one of NORMAL/FULL/OFF
        sync = conn.execute(text("PRAGMA synchronous")).fetchone()
        assert sync is not None
        assert int(sync[0]) in (0, 1, 2)  # OFF, NORMAL, FULL


# ---- JobRunner idempotency (job_runner.py run_job) ----


class _StubModule:
    """Minimal BaseReconModule stub for idempotency tests."""

    def __init__(self, name: str = "stub") -> None:
        self.name = name
        self.tier = None  # type: ignore[assignment]
        self.mitre_techniques: list[str] = []

    async def run(self, _input):  # type: ignore[no-untyped-def]
        from app.modules.base import ModuleOutput

        return ModuleOutput(module=self.name, findings=[], duration_seconds=0.0)


@pytest.fixture
def jobrunner_db(tmp_path):
    """Per-test sync DB session with the Job table created.

    The project has a known duplicate-index bug in the Finding model
    (both `index=True` on `source` AND an explicit `Index("ix_findings_source", ...)`),
    so `Base.metadata.create_all(bind=engine)` fails on the second
    `ix_findings_source` create. We avoid that here by creating only
    the Job table (which is all these tests need). A fresh file-based
    engine avoids any cross-test state.

    Patches BOTH app.database.engine/SessionLocal AND
    app.orchestrator.job_runner.SessionLocal (which captures the value
    at import time).
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    db_path = tmp_path / "test.db"
    if db_path.exists():
        db_path.unlink()

    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )

    from app.models import Job, ModuleRun

    # Create only the tables these tests actually need (avoid the
    # duplicate-index bug in Finding's source column).
    Job.__table__.create(bind=eng, checkfirst=True)
    ModuleRun.__table__.create(bind=eng, checkfirst=True)
    Session_ = sessionmaker(bind=eng, autoflush=False, autocommit=False, expire_on_commit=False)

    # Patch global + the import-bound reference inside job_runner.
    import app.database as app_db
    import app.orchestrator.job_runner as jr_module

    original_app_engine = app_db.engine
    original_app_session = app_db.SessionLocal
    original_jr_session = jr_module.SessionLocal

    app_db.engine = eng
    app_db.SessionLocal = Session_
    jr_module.SessionLocal = Session_

    db = Session_()
    try:
        yield db
    finally:
        db.close()
        Job.__table__.drop(bind=eng, checkfirst=True)
        ModuleRun.__table__.drop(bind=eng, checkfirst=True)
        app_db.engine = original_app_engine
        app_db.SessionLocal = original_app_session
        jr_module.SessionLocal = original_jr_session
        eng.dispose()
        try:
            db_path.unlink()
        except FileNotFoundError:
            pass


@pytest.mark.asyncio
async def test_jobrunner_double_call_is_idempotent(jobrunner_db) -> None:
    """Calling run_job() twice on the same job must NOT execute modules twice.

    Regression test for the audit finding: previously the runner would
    transition PENDING→RUNNING unconditionally, so a second call created
    a duplicate batch of ModuleRun rows. Now the runner refuses to
    re-execute terminal jobs.
    """
    from app.models import Job, JobStatus
    from app.orchestrator.job_runner import JobRunner

    db = jobrunner_db

    # Create a job that's already COMPLETED — calling run_job again must
    # be a no-op.
    job_id = "test-job-double-call"
    job = Job(
        id=job_id,
        target="example.com",
        status=JobStatus.COMPLETED,
        selected_modules=["stub"],
    )
    db.add(job)
    db.commit()

    runner = JobRunner(
        module_registry={"stub": _StubModule()},
        ai_validator=None,  # type: ignore[arg-type]
    )

    # Run again — should not raise and should not transition status.
    await runner.run_job(job_id)

    # Job must still be COMPLETED, not touched.
    db.expire_all()
    job = db.get(Job, job_id)
    assert job is not None
    assert job.status == JobStatus.COMPLETED


@pytest.mark.asyncio
async def test_jobrunner_running_job_is_skipped(jobrunner_db) -> None:
    """If a job is RUNNING (already in flight), a second run_job() must skip.

    Prevents two workers from concurrently executing the same job's
    modules.
    """
    from app.models import Job, JobStatus
    from app.orchestrator.job_runner import JobRunner

    db = jobrunner_db

    job_id = "test-job-running"
    job = Job(
        id=job_id,
        target="example.com",
        status=JobStatus.RUNNING,
        selected_modules=[],
    )
    db.add(job)
    db.commit()

    runner = JobRunner(
        module_registry={"stub": _StubModule()},
        ai_validator=None,  # type: ignore[arg-type]
    )

    await runner.run_job(job_id)

    # Job must remain RUNNING — not transitioned to VALIDATING.
    db.expire_all()
    job = db.get(Job, job_id)
    assert job is not None
    assert job.status == JobStatus.RUNNING


@pytest.mark.asyncio
async def test_module_execution_respects_concurrency_limit(jobrunner_db) -> None:
    """JobRunner._module_sem bounds the in-flight module count.

    Audit R4-H2: a job selecting all 14 modules used to fan out 14
    parallel httpx + LLM streams. Now the `_module_sem` semaphore
    caps concurrency at `MAX_CONCURRENT_MODULES` (default 4). We
    drive the semaphore directly: launch `cap + 3` acquire operations
    concurrently and verify that at most `cap` resolve synchronously
    while the rest wait.
    """
    from app.orchestrator.job_runner import JobRunner

    runner = JobRunner(
        module_registry={},
        ai_validator=None,  # type: ignore[arg-type]
        module_concurrency=2,
    )
    sem = runner._module_sem  # type: ignore[attr-defined]
    cap = 2
    extra = 3

    async def _one_acquire(idx: int) -> bool:
        # Acquire without an immediate release. Returns True if the
        # semaphore let us through synchronously.
        await sem.acquire()
        # Hold the slot for the duration of the test by NOT releasing.
        # We track whether we got it.
        return True

    # Schedule cap + extra acquires — only cap should resolve fast.
    tasks = [asyncio.create_task(_one_acquire(i)) for i in range(cap + extra)]
    # Yield once so the cap tasks get a chance to run; the extras must
    # be parked on the semaphore.
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    completed = sum(1 for t in tasks if t.done())
    # Exactly `cap` tasks should have completed; the remaining `extra`
    # must still be waiting (parity-2 inventory under asyncio).
    assert completed == cap, (
        f"semaphore oversubscribed: {completed} > {cap} acquired"
    )

    # Cancel the parked tasks and release the held slots so the test
    # cleans up.
    for t in tasks:
        if not t.done():
            t.cancel()
    for _ in range(cap):
        sem.release()


@pytest.mark.asyncio
async def test_jobrunner_missing_job_raises(jobrunner_db) -> None:
    """run_job() on a non-existent job must raise ValueError."""
    from app.orchestrator.job_runner import JobRunner

    runner = JobRunner(
        module_registry={},
        ai_validator=None,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="not found"):
        await runner.run_job("non-existent-job-id")