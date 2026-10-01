"""Job queue and job state (memory for tests and single-process dev; Redis
for anything shared between the API and the dispatcher)."""

from __future__ import annotations

import threading
from collections import deque
from typing import Protocol

from .models import Job, now

JOB_TTL_S = 24 * 3600


class QueueFull(RuntimeError):
    pass


class JobQueue(Protocol):
    def submit(self, job: Job, cap: int) -> None: ...
    def next(self, timeout_s: float) -> str | None: ...
    def get(self, job_id: str) -> Job | None: ...
    def update(self, job: Job) -> None: ...
    def depth(self) -> int: ...


class MemoryQueue:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._q: deque[str] = deque()
        self._cv = threading.Condition()

    def submit(self, job: Job, cap: int) -> None:
        with self._cv:
            if len(self._q) >= cap:
                raise QueueFull("the scan queue is full")
            self._jobs[job.id] = job
            self._q.append(job.id)
            self._cv.notify()

    def next(self, timeout_s: float) -> str | None:
        with self._cv:
            if not self._q:
                self._cv.wait(timeout_s)
            return self._q.popleft() if self._q else None

    def get(self, job_id: str) -> Job | None:
        job = self._jobs.get(job_id)
        return job.model_copy() if job else None

    def update(self, job: Job) -> None:
        job.updated_at = now()
        with self._cv:
            self._jobs[job.id] = job.model_copy()

    def depth(self) -> int:
        return len(self._q)


class RedisQueue:
    def __init__(self, url: str) -> None:
        import redis

        self._r = redis.Redis.from_url(url)

    def submit(self, job: Job, cap: int) -> None:
        if self._r.llen("agw:queue") >= cap:
            raise QueueFull("the scan queue is full")
        self._r.set(f"agw:job:{job.id}", job.model_dump_json(), ex=JOB_TTL_S)
        self._r.rpush("agw:queue", job.id)

    def next(self, timeout_s: float) -> str | None:
        item = self._r.blpop(["agw:queue"], timeout=max(1, int(timeout_s)))
        return item[1].decode() if item else None

    def get(self, job_id: str) -> Job | None:
        raw = self._r.get(f"agw:job:{job_id}")
        return Job.model_validate_json(raw) if raw else None

    def update(self, job: Job) -> None:
        job.updated_at = now()
        self._r.set(f"agw:job:{job.id}", job.model_dump_json(), ex=JOB_TTL_S)

    def depth(self) -> int:
        return int(self._r.llen("agw:queue"))


def make_queue(url: str) -> JobQueue:
    if url == "memory":
        return MemoryQueue()
    if url.startswith(("redis://", "rediss://")):
        return RedisQueue(url)
    raise ValueError("AGW_QUEUE must be memory or redis://...")
