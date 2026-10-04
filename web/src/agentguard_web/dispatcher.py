"""The dispatcher: takes jobs off the queue and runs the pipeline.

It is the only process with network egress (through the Fetcher's allowlist)
and the only one allowed to start scanner sandboxes."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from .config import Settings
from .fetch import Fetcher
from .pipeline import Pipeline
from .queue import JobQueue
from .sandbox import make_sandbox
from .store import ReportStore

log = logging.getLogger("agentguard_web.dispatcher")


def build_pipeline(settings: Settings, queue: JobQueue, store: ReportStore) -> Pipeline:
    return Pipeline(
        queue=queue, store=store,
        sandbox=make_sandbox(settings.sandbox, settings.scanner_image, settings.docker_runtime),
        fetcher=Fetcher(github_token=settings.github_token, max_archive_bytes=settings.max_archive_bytes,
                        extra_hosts=settings.extra_allowed_hosts),
        timeout_s=settings.job_timeout_s,
        remote_cache_s=settings.remote_cache_s,
    )


def run(settings: Settings, queue: JobQueue, store: ReportStore, stop: threading.Event | None = None) -> None:
    stop = stop or threading.Event()
    pool = ThreadPoolExecutor(max_workers=max(1, settings.workers), thread_name_prefix="agw-job")
    slots = threading.Semaphore(max(1, settings.workers))
    log.info("dispatcher started: sandbox=%s workers=%d", settings.sandbox, settings.workers)

    def work(job_id: str) -> None:
        try:
            # A fresh pipeline (and fresh HTTP clients) per job: nothing carries over between jobs.
            build_pipeline(settings, queue, store).process(job_id)
        finally:
            slots.release()

    while not stop.is_set():
        slots.acquire()
        job_id = queue.next(timeout_s=2)
        if job_id is None:
            slots.release()
            continue
        pool.submit(work, job_id)
    pool.shutdown(wait=True)
