"""Jobs and stored reports. The findings JSON (schemas/report.v1.json) is the
only thing stored about a scan; archives are never written anywhere."""

from __future__ import annotations

import datetime as dt
import secrets
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class JobStatus(StrEnum):
    queued = "queued"
    resolving = "resolving"
    fetching = "fetching"
    scanning = "scanning"
    done = "done"
    error = "error"


def new_job_id() -> str:
    return secrets.token_hex(12)


def now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


class Job(BaseModel):
    id: str = Field(default_factory=new_job_id)
    input: str
    status: JobStatus = JobStatus.queued
    detail: str = ""
    report_key: str | None = None
    cached: bool = False
    error: str | None = None
    supported: list[str] = Field(default_factory=list)
    created_at: dt.datetime = Field(default_factory=now)
    updated_at: dt.datetime = Field(default_factory=now)

    def public(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"input"}) | {"input": self.input[:300]}


class StoredReport(BaseModel):
    key: str
    kind: str
    locator: str
    resolved: str
    rule_pack_version: str
    engine_version: str
    scanned_at: dt.datetime
    report_json: str
