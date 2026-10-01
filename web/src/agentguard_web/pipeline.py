"""One job, start to finish: parse → resolve → cache → fetch → isolated scan → store."""

from __future__ import annotations

import datetime as dt
import logging

from agentguard.core.cachekey import report_cache_key
from agentguard.core.engine import ENGINE_VERSION
from agentguard.core.inputs import ParsedInput, parse
from agentguard.core.models import ImmutableRef, Report, RulePackInfo
from agentguard.core.rules.pack import RulePack
from agentguard.net.safe_http import BlockedRequest, FetchError

from .fetch import Fetcher
from .models import Job, JobStatus, StoredReport
from .queue import JobQueue
from .resolve import ResolveError, Resolver, plan_archive
from .sandbox import Sandbox, SandboxError
from .store import ReportStore

log = logging.getLogger("agentguard_web.pipeline")


def local_rule_pack() -> RulePackInfo:
    pack = RulePack.default()
    return RulePackInfo(version=pack.version, digest=pack.digest, rule_count=len(pack.rules))


class Pipeline:
    def __init__(self, *, queue: JobQueue, store: ReportStore, sandbox: Sandbox, fetcher: Fetcher,
                 timeout_s: int = 120) -> None:
        self.queue = queue
        self.store = store
        self.sandbox = sandbox
        self.fetcher = fetcher
        self.resolver = Resolver(fetcher)
        self.timeout_s = timeout_s
        self.pack = local_rule_pack()

    def _set(self, job: Job, status: JobStatus, detail: str = "") -> None:
        job.status = status
        job.detail = detail
        self.queue.update(job)

    def process(self, job_id: str) -> Job | None:
        job = self.queue.get(job_id)
        if job is None:
            return None
        try:
            self._run(job)
        except (ResolveError, SandboxError) as exc:
            job.error = str(exc)
            self._set(job, JobStatus.error)
        except BlockedRequest as exc:
            job.error = f"Refused by the fetcher's safety policy: {exc}"
            self._set(job, JobStatus.error)
        except FetchError as exc:
            job.error = f"Could not fetch the source: {exc}"
            self._set(job, JobStatus.error)
        except Exception:  # noqa: BLE001 - never leave a job hanging
            log.exception("job %s failed", job.id)
            job.error = "The scanner failed unexpectedly. Please try again later."
            self._set(job, JobStatus.error)
        return job

    def _run(self, job: Job) -> None:
        self._set(job, JobStatus.resolving, "Resolving to an exact commit or version")
        parsed = parse(job.input)
        if not isinstance(parsed, ParsedInput):
            job.supported = list(parsed.supported)
            raise ResolveError(parsed.reason)
        resolved = self.resolver.resolve(parsed)
        key = report_cache_key(resolved.ref, self.pack, ENGINE_VERSION)
        if self.store.get(key) is not None:
            job.report_key, job.cached = key, True
            self._set(job, JobStatus.done, "Already scanned with this rule pack")
            return
        self._set(job, JobStatus.fetching, f"Downloading {resolved.ref.locator}@{resolved.ref.resolved[:12]}")
        archive = plan_archive(self.fetcher, resolved)
        self._set(job, JobStatus.scanning, f"Scanning in an isolated sandbox ({len(archive) // 1024} KB)")
        spec = {
            "source": resolved.source_json(),
            "strip_components": resolved.strip_components,
            "subpath": resolved.subpath,
            "events": [e.model_dump(mode="json") for e in resolved.notes],
            "extra_files": resolved.extra_files,
        }
        report_json = self.sandbox.run(archive, spec, self.timeout_s)
        del archive  # never kept
        report = Report.model_validate_json(report_json)
        if not isinstance(report.target, ImmutableRef) or report.target.resolved != resolved.ref.resolved:
            raise SandboxError("the scanner's report does not match the requested source")
        # Key by what actually scanned (the sandbox image's rule pack and engine).
        key = report_cache_key(resolved.ref, report.rule_pack, report.engine_version)
        self.store.put(StoredReport(
            key=key, kind=resolved.ref.kind.value, locator=resolved.ref.locator, resolved=resolved.ref.resolved,
            rule_pack_version=report.rule_pack.version, engine_version=report.engine_version,
            scanned_at=dt.datetime.now(dt.UTC), report_json=report_json,  # full precision: orders rescans
        ))
        job.report_key = key
        self._set(job, JobStatus.done, report.summary)
