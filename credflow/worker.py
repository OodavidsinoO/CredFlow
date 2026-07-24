"""Concurrency management — parallel scan execution via ThreadPoolExecutor."""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from credflow.config import Config
from credflow.scanner import NessusClient, run_scan_job
from credflow.state import StateManager

logger = logging.getLogger(__name__)

MAX_WORKERS_HARD_CAP = 50

# Exception types considered transient (retryable)
_TRANSIENT_EXCEPTIONS = (
    ConnectionError,
    TimeoutError,
    OSError,
)


def worker_loop(
    client: NessusClient,
    config: Config,
    state: StateManager,
    template_uuid: str,
    plugins: dict | None = None,
    scan_name_prefix: str = "CredFlow",
    stop_event: threading.Event | None = None,
) -> int:
    """Single worker: claim → scan → repeat until no pending targets or stop signal.
    Returns count of completed jobs."""
    completed = 0
    while True:
        if stop_event is not None and stop_event.is_set():
            logger.info("Worker stopping due to shutdown signal")
            break
        target = state.claim_next()
        if target is None:
            break
        try:
            run_scan_job(target, client, config, state, template_uuid, plugins=plugins, scan_name_prefix=scan_name_prefix)
            completed += 1
        except _TRANSIENT_EXCEPTIONS:
            logger.debug("Worker continuing after transient failure", exc_info=True)
        except Exception:
            logger.warning("Worker continuing after permanent failure", exc_info=True)
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
    shutdown_event: threading.Event | None = None,
) -> dict:
    """Load targets into state DB and execute scans with configurable concurrency.
    Returns summary dict {total, completed, failed, ...}.
    """
    # Load targets into state DB
    new_count = state.load_targets(targets)
    progress_before = state.get_progress()

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

    # Resolve template UUID and plugins once
    client = NessusClient(config)

    plugins: dict | None = None
    scan_name_prefix = config.scan_name_prefix

    if config.source_scan_name:
        source_scan = client.find_scan_by_name(config.source_scan_name)
        if source_scan:
            source_scan_id = source_scan.get("id")
            logger.info(
                "Found source scan '%s' (id=%s) — loading full config",
                source_scan.get("name"),
                source_scan_id,
            )
            try:
                scan_config = client.get_scan_config(source_scan_id)
                # Use the template UUID from the source scan
                src_template_uuid = scan_config.get("uuid")
                if src_template_uuid:
                    config.template_uuid = src_template_uuid
                    logger.info(
                        "Using template from source scan: '%s' → %s",
                        scan_config.get("title", scan_config.get("name")),
                        src_template_uuid,
                    )
                # Extract plugin settings from source scan
                source_plugins = client.extract_plugins_from_config(scan_config)
                if source_plugins:
                    plugins = source_plugins
                    disabled_count = len(source_plugins)
                    logger.info(
                        "Inherited %d modified plugin families from source scan",
                        disabled_count,
                    )
                # Default name prefix from source scan
                if not scan_name_prefix:
                    scan_name_prefix = source_scan.get("name", "CredFlow")
            except Exception as e:
                logger.warning(
                    "Could not load source scan config: %s — falling back to template",
                    e,
                )
        else:
            logger.warning(
                "Source scan '%s' not found — using template '%s'",
                config.source_scan_name,
                config.template_name,
            )

    template_uuid = client.get_template_uuid(config.template_name)

    # Apply disabled_plugin_families config (merges with source scan plugins)
    disabled_names: list[str] = []
    if config.disabled_plugin_families:
        disabled_names = [
            n.strip() for n in config.disabled_plugin_families.split(",") if n.strip()
        ]
    if disabled_names:
        config_plugins = client.resolve_disabled_families(disabled_names, template_uuid)
        if config_plugins:
            if plugins:
                # Merge: config list overrides source scan for same families
                for name, fam in config_plugins.items():
                    plugins[name] = fam
            else:
                plugins = config_plugins
            logger.info(
                "Plugin families will be disabled: %s",
                ", ".join(plugins.keys()) if plugins else "none",
            )

    # Determine scan name prefix
    if not scan_name_prefix:
        scan_name_prefix = "CredFlow"
    logger.info("Scan name prefix: '%s'", scan_name_prefix)

    # Cap workers
    workers = max(1, min(config.max_workers, pending_before, MAX_WORKERS_HARD_CAP))
    logger.info("Starting %d worker(s) for %d pending target(s)", workers, pending_before)

    batch_start = time.monotonic()
    stop_event = threading.Event()

    # Watch for batch timeout or external shutdown signal
    def _watch_stop() -> None:
        if shutdown_event is not None:
            shutdown_event.wait()
            logger.info("Shutdown signal received — stopping workers")
        elif config.batch_timeout > 0:
            elapsed = time.monotonic() - batch_start
            remaining = config.batch_timeout - elapsed
            if remaining > 0:
                time.sleep(remaining)
            logger.info("Batch timeout (%ds) reached — stopping workers", config.batch_timeout)
        stop_event.set()

    if shutdown_event is not None or config.batch_timeout > 0:
        watcher = threading.Thread(target=_watch_stop, daemon=True)
        watcher.start()

    reporter_thread = threading.Thread(
        target=progress_reporter, args=(state, stop_event), daemon=True
    )
    reporter_thread.start()

    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = []
        for _ in range(workers):
            worker_client = NessusClient(config)
            futures.append(
                executor.submit(
                    worker_loop,
                    worker_client,
                    config,
                    state,
                    template_uuid,
                    plugins,
                    scan_name_prefix,
                    stop_event=stop_event,
                )
            )

        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                logger.error("Worker thread crashed", exc_info=True)
    finally:
        stop_event.set()
        executor.shutdown(wait=True)
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
