"""One job, start to finish.

* scan: parse → resolve → cache → fetch → isolated scan → store. A remote MCP
  server URL is probed read-only instead of downloaded, and the recorded probe
  is scanned in the same isolated sandbox.
* response: read a maintainer's ``.agentguard/response.md`` from the project's
  repository and attach it to a report (see responses.py).
"""

from __future__ import annotations

import datetime as dt
import json
import logging
from collections.abc import Callable

from agentguard.core.cachekey import report_cache_key
from agentguard.core.engine import ENGINE_VERSION
from agentguard.core.inputs import ParsedInput, parse
from agentguard.core.models import ImmutableRef, Report, RulePackInfo
from agentguard.core.models.enums import SourceKind
from agentguard.core.rules.pack import RulePack
from agentguard.net.safe_http import BlockedRequest, FetchError, SafeHttpClient
from agentguard.webscan import remote_fingerprint

from .fetch import Fetcher
from .models import Job, JobKind, JobStatus, MaintainerResponse, StoredReport
from .probe import ProbeClient, probe_remote, unreachable
from .queue import JobQueue
from .resolve import RemoteServer, ResolveError, Resolver, plan_archive
from .responses import RESPONSE_PATH, ResponseError, parse_response, read_response, repository_for
from .sandbox import Sandbox, SandboxError
from .store import ReportStore

log = logging.getLogger("agentguard_web.pipeline")


def local_rule_pack() -> RulePackInfo:
    pack = RulePack.default()
    return RulePackInfo(version=pack.version, digest=pack.digest, rule_count=len(pack.rules))


class Pipeline:
    def __init__(self, *, queue: JobQueue, store: ReportStore, sandbox: Sandbox, fetcher: Fetcher,
                 timeout_s: int = 120, prober: Callable[[], SafeHttpClient] = ProbeClient,
                 remote_cache_s: int = 600) -> None:
        self.queue = queue
        self.store = store
        self.sandbox = sandbox
        self.fetcher = fetcher
        self.resolver = Resolver(fetcher)
        self.timeout_s = timeout_s
        self.prober = prober
        self.remote_cache_s = remote_cache_s
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
            if job.kind == JobKind.response:
                self._run_response(job)
            else:
                self._run(job)
        except (ResolveError, SandboxError, ResponseError) as exc:
            job.error = str(exc)
            self._set(job, JobStatus.error)
        except BlockedRequest as exc:
            job.error = f"Refused by the network safety policy: {exc}"
            self._set(job, JobStatus.error)
        except FetchError as exc:
            job.error = f"Could not fetch the source: {exc}"
            self._set(job, JobStatus.error)
        except Exception:  # noqa: BLE001 - never leave a job hanging
            log.exception("job %s failed", job.id)
            job.error = "The scanner failed unexpectedly. Please try again later."
            self._set(job, JobStatus.error)
        return job

    # -- scans -------------------------------------------------------------------
    def _run(self, job: Job) -> None:
        self._set(job, JobStatus.resolving, "Resolving to an exact commit or version")
        parsed = parse(job.input)
        if not isinstance(parsed, ParsedInput):
            job.supported = list(parsed.supported)
            raise ResolveError(parsed.reason)
        try:
            resolved = self.resolver.resolve(parsed)
        except RemoteServer as remote:
            return self._run_remote(job, remote.url)
        key = report_cache_key(resolved.ref, self.pack, ENGINE_VERSION)
        if self.store.get(key) is not None:
            return self._cached(job, key)
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
        self._store(job, resolved.ref, report_json)

    def _run_remote(self, job: Job, url: str) -> None:
        recent = self.store.previous(SourceKind.remote_mcp.value, url, dt.datetime.now(dt.UTC))
        if recent is not None and self._current(recent) and \
                dt.datetime.now(dt.UTC) - recent.scanned_at < dt.timedelta(seconds=self.remote_cache_s):
            job.report_key, job.cached = recent.key, True
            age = int((dt.datetime.now(dt.UTC) - recent.scanned_at).total_seconds() // 60)
            self._set(job, JobStatus.done, f"Checked {age} min ago with this rule pack; showing that report")
            return
        self._set(job, JobStatus.fetching, f"Querying {url} (read-only: discovery and list methods, OAuth metadata)")
        client = self.prober()
        probe = probe_remote(client, url)
        if (exc := unreachable(probe)) is not None:
            raise exc
        ref = ImmutableRef(kind=SourceKind.remote_mcp, locator=url, resolved=remote_fingerprint(probe))
        key = report_cache_key(ref, self.pack, ENGINE_VERSION)
        if self.store.get(key) is not None:
            return self._cached(job, key)
        self._set(job, JobStatus.scanning, f"Scanning the server's metadata in an isolated sandbox ({len(probe.tools)} tools)")
        spec = {"mode": "remote_mcp", "source": ref.model_dump(mode="json", exclude={"source_url_template"}),
                "hosts": sorted(client.hosts_contacted)}
        report_json = self.sandbox.run(probe.model_dump_json().encode("utf-8"), spec, self.timeout_s)
        self._store(job, ref, report_json)

    def _current(self, rec: StoredReport) -> bool:
        try:
            digest = json.loads(rec.report_json)["rule_pack"]["digest"]
        except (ValueError, KeyError, TypeError):
            return False
        return digest == self.pack.digest and rec.engine_version == ENGINE_VERSION

    def _cached(self, job: Job, key: str) -> None:
        job.report_key, job.cached = key, True
        self._set(job, JobStatus.done, "Already scanned with this rule pack")

    def _store(self, job: Job, ref: ImmutableRef, report_json: str) -> None:
        report = Report.model_validate_json(report_json)
        if not isinstance(report.target, ImmutableRef) or report.target.resolved != ref.resolved:
            raise SandboxError("the scanner's report does not match the requested source")
        # Key by what actually scanned (the sandbox image's rule pack and engine).
        key = report_cache_key(ref, report.rule_pack, report.engine_version)
        self.store.put(StoredReport(
            key=key, kind=ref.kind.value, locator=ref.locator, resolved=ref.resolved,
            rule_pack_version=report.rule_pack.version, engine_version=report.engine_version,
            scanned_at=dt.datetime.now(dt.UTC), report_json=report_json,  # full precision: orders rescans
        ))
        job.report_key = key
        self._set(job, JobStatus.done, report.summary)

    # -- maintainer responses ------------------------------------------------------
    def _run_response(self, job: Job) -> None:
        key = job.target_key or ""
        rec = self.store.get(key)
        if rec is None:
            raise ResponseError("That report does not exist or has expired.")
        self._set(job, JobStatus.resolving, "Finding the project's GitHub repository")
        owner, repo = repository_for(self.fetcher, rec)
        self._set(job, JobStatus.fetching, f"Reading {RESPONSE_PATH} from github.com/{owner}/{repo}")
        sha, text = read_response(self.fetcher, owner, repo)
        body = parse_response(text, key)
        job.report_key = key
        if not body:
            self.store.delete_response(key)
            self._set(job, JobStatus.done, "Response removed: the file names this report but has no text")
            return
        self.store.put_response(MaintainerResponse(report_key=key, text=body, repository=f"{owner}/{repo}", commit=sha))
        self._set(job, JobStatus.done, f"Response attached from github.com/{owner}/{repo} at {sha[:12]}")
