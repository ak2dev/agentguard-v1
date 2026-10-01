"""Settings from AGW_* environment variables. Production refuses unsafe options."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"AGW_{name}", default)


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    mode: str = "dev"                       # dev | prod
    store: str = "sqlite:///./agentguard-web.db"   # sqlite:///path | postgresql://...
    queue: str = "memory"                   # memory | redis://...
    sandbox: str = "docker"                 # docker | inprocess (dev/tests only)
    scanner_image: str = "agentguard-scanner:local"
    docker_runtime: str = ""                # e.g. "runsc" (gVisor) when installed
    github_token: str = ""                  # optional; raises the GitHub API limit (fetcher only)
    allowed_origins: tuple[str, ...] = ()   # CORS for a site on another origin
    trust_proxy: bool = False               # use X-Forwarded-For (only behind a trusted proxy)
    rate_per_minute: int = 6
    rate_per_day: int = 60
    queue_cap: int = 50
    max_archive_bytes: int = 50 * 1024 * 1024
    job_timeout_s: int = 120
    retention_days: int = 90
    workers: int = 2
    extra_allowed_hosts: tuple[str, ...] = field(default_factory=tuple)  # configured marketplaces

    @classmethod
    def from_env(cls) -> Settings:
        s = cls(
            mode=_env("MODE", "dev"),
            store=_env("STORE", cls.store),
            queue=_env("QUEUE", cls.queue),
            sandbox=_env("SANDBOX", cls.sandbox),
            scanner_image=_env("SCANNER_IMAGE", cls.scanner_image),
            docker_runtime=_env("DOCKER_RUNTIME", ""),
            github_token=_env("GITHUB_TOKEN", ""),
            allowed_origins=tuple(o for o in _env("ALLOWED_ORIGINS").split(",") if o),
            trust_proxy=_env("TRUST_PROXY") == "1",
            rate_per_minute=_int("RATE_PER_MINUTE", cls.rate_per_minute),
            rate_per_day=_int("RATE_PER_DAY", cls.rate_per_day),
            queue_cap=_int("QUEUE_CAP", cls.queue_cap),
            max_archive_bytes=_int("MAX_ARCHIVE_BYTES", cls.max_archive_bytes),
            job_timeout_s=_int("JOB_TIMEOUT_S", cls.job_timeout_s),
            retention_days=_int("RETENTION_DAYS", cls.retention_days),
            workers=_int("WORKERS", cls.workers),
            extra_allowed_hosts=tuple(h for h in _env("EXTRA_ALLOWED_HOSTS").split(",") if h),
        )
        s.validate()
        return s

    def validate(self) -> None:
        if self.mode == "prod":
            if self.sandbox != "docker":
                raise ValueError("AGW_SANDBOX must be 'docker' in production: scans must run isolated")
            if self.queue == "memory":
                raise ValueError("AGW_QUEUE must be a Redis URL in production")
        if self.sandbox not in ("docker", "inprocess"):
            raise ValueError(f"unknown AGW_SANDBOX {self.sandbox!r}")
