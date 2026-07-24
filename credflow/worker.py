"""Concurrency management — parallel scan execution via ThreadPoolExecutor."""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from credflow.config import Config
from credflow.scanner import NessusClient, run_scan_job
from credflow.state import StateManager

logger = logging.getLogger(__name__)

MAX_WORKERS_HARD_CAP = 5


def worker_loop(
    client: NessusClient,
    config: Config,
    state: StateManager,
    template_uuid: str,
) -> int:
    """Single worker: claim → scan → repeat until no pending targets.
    Returns count of completed jobs."""
    completed = 0
    while True:
        target = state.claim_next()
        if target is None:
            break
        try:
            run_scan_job(target, client, config, state, template_uuid)
            completed += 1
        except Exception:
            # run_scan_job already logged the error and updated state;
            # we just continue to the next target
            logger.debug("Worker continuing after failed job for target", exc_info=True)
    return completed


def progress_reporter(state: StateManager, stop_event: threading.Event) -> None:
    """Background thread: report progress every 10 seconds."""
    while not stop_event.wait(10):
        progress = state.get_progress()
        total = sum(progress.values())
        if total > 0:
            parts = []
            for status in ("completed", "running", "pending", "failed"):
                count = progress.get(status, 0)
                if count:
                    parts.append(f"{status}={count}")
            logger.info("Progress: %s (total=%d)", " | ".join(parts), total)


def run_batch(
    targets: list,
    config: Config,
    state: StateManager,
) -> dict:
    """Load targets into state DB and execute scans with configurable concurrency.
    Returns summary dict {total, completed, failed, ...}.
    """
    # Load targets into state DB
    new_count = state.load_targets(targets)
    progress_before = state.get_progress()
    total = sum(progress_before.values())

    pending_before = progress_before.get("pending", 0)
    logger.info(
        "Loaded %d new target(s) — %d pending, %d already completed",
        new_count,
        pending_before,
        progress_before.get("completed", 0),
    )

    if pending_before == 0:
        logger.info("No pending targets. All done!")
        return _build_summary(state)

    # Resolve template UUID once
    client = NessusClient(config)
    template_uuid = client.get_template_uuid(config.template_name)

    # Cap workers
    workers = max(1, min(config.max_workers, pending_before, MAX_WORKERS_HARD_CAP))
    logger.info("Starting %d worker(s) for %d pending target(s)", workers, pending_before)

    stop_event = threading.Event()
    reporter_thread = threading.Thread(
        target=progress_reporter, args=(state, stop_event), daemon=True
    )
    reporter_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for _ in range(workers):
                worker_client = NessusClient(config)
                futures.append(
                    executor.submit(
                        worker_loop, worker_client, config, state, template_uuid
                    )
                )

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    logger.error("Worker thread crashed", exc_info=True)
    finally:
        stop_event.set()
        reporter_thread.join(timeout=5)

    return _build_summary(state)


def _build_summary(state: StateManager) -> dict:
    """Build final summary from state DB."""
    progress = state.get_progress()
    failures = state.get_failures()
    reports = state.get_completed_reports()
    return {
        "total": sum(progress.values()),
        "completed": progress.get("completed", 0),
        "failed": progress.get("failed", 0),
        "pending": progress.get("pending", 0),
        "failures": failures,
        "reports": reports,
    }
