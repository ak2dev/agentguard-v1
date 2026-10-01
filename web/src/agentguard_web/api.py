"""Agent Guard Web API.

    POST /api/scans                 {"input": "<link or package>"}  → 202 {id, status, ...}
    GET  /api/scans/{id}            job status
    GET  /api/scans/{id}/events     server-sent events until the job finishes
    GET  /api/reports/{key}         report JSON; ?format=sarif|markdown|html|cyclonedx
    GET  /api/reports/{key}/diff    drift against the previous scan of the same source
    GET  /api/health

The API has no network egress: it validates input, rate-limits, queues the
job and serves stored reports. Resolution and fetching happen in the
dispatcher; scanning happens in the isolated sandbox. Reports are findings,
not verdicts, and are unlisted: reachable only by their key.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from agentguard.core.cachekey import diff_reports
from agentguard.core.engine import ENGINE_VERSION
from agentguard.core.inputs import ParsedInput, parse
from agentguard.core.models import Report
from agentguard.core.report.html import render_html
from agentguard.core.report.render import render_cyclonedx, render_markdown, render_sarif

from .config import Settings
from .models import Job, JobStatus
from .pipeline import local_rule_pack
from .queue import JobQueue, QueueFull
from .ratelimit import RateLimiter, client_id
from .store import ReportStore

_KEY = re.compile(r"^[0-9a-f]{32}$")
_JOB = re.compile(r"^[0-9a-f]{24}$")
_FORMATS = {
    "sarif": ("application/sarif+json", "sarif", render_sarif),
    "markdown": ("text/markdown; charset=utf-8", "md", render_markdown),
    "html": ("text/html; charset=utf-8", "html", render_html),
    "cyclonedx": ("application/vnd.cyclonedx+json", "cdx.json", render_cyclonedx),
}
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-site",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
}


class ScanRequest(BaseModel):
    input: str = Field(min_length=1, max_length=2048)


def create_app(settings: Settings, *, queue: JobQueue, store: ReportStore, limiter: RateLimiter) -> FastAPI:
    app = FastAPI(title="Agent Guard Web", docs_url=None, redoc_url=None, openapi_url=None)
    if settings.allowed_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.allowed_origins),
                           allow_methods=["GET", "POST"], allow_headers=["Content-Type"], max_age=600)
    pack = local_rule_pack()

    @app.middleware("http")
    async def headers(request: Request, call_next):  # noqa: ANN001, ANN202
        if int(request.headers.get("content-length") or 0) > 8192:
            return JSONResponse({"error": "request too large"}, status_code=413)
        resp = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    def client(request: Request) -> str:
        addr = request.client.host if request.client else "unknown"
        if settings.trust_proxy:
            fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            addr = fwd or addr
        return client_id(addr)

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "engine_version": ENGINE_VERSION, "rule_pack": pack.model_dump(), "queue_depth": queue.depth()}

    @app.post("/api/scans", status_code=202)
    def submit(body: ScanRequest, request: Request) -> JSONResponse:
        parsed = parse(body.input)
        if not isinstance(parsed, ParsedInput):
            return JSONResponse({"error": parsed.reason, "supported": parsed.supported}, status_code=400)
        if parsed.source.kind.value == "remote_mcp":
            return JSONResponse({"error": "Remote MCP server checks are not available on the hosted service yet. "
                                          "Use the CLI with --live-metadata --auth-checks."}, status_code=422)
        wait = limiter.hit(client(request))
        if wait is not None:
            return JSONResponse({"error": "Too many scans from your network; please wait."}, status_code=429,
                                headers={"Retry-After": str(wait)})
        job = Job(input=body.input.strip())
        try:
            queue.submit(job, settings.queue_cap)
        except QueueFull:
            return JSONResponse({"error": "The scanner is busy; please try again in a minute."}, status_code=503,
                                headers={"Retry-After": "60"})
        return JSONResponse(_job_view(job), status_code=202)

    def _job(job_id: str) -> Job:
        if not _JOB.match(job_id):
            raise HTTPException(404, "no such scan")
        job = queue.get(job_id)
        if job is None:
            raise HTTPException(404, "no such scan")
        return job

    @app.get("/api/scans/{job_id}")
    def status(job_id: str) -> dict:
        return _job_view(_job(job_id))

    @app.get("/api/scans/{job_id}/events")
    async def events(job_id: str) -> StreamingResponse:
        _job(job_id)

        async def stream() -> AsyncIterator[bytes]:
            last = None
            for _ in range(int(settings.job_timeout_s * 2 + 120)):
                job = queue.get(job_id)
                if job is None:
                    break
                view = json.dumps(_job_view(job))
                if view != last:
                    last = view
                    yield f"data: {view}\n\n".encode()
                if job.status in (JobStatus.done, JobStatus.error):
                    break
                await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})

    def _report(key: str):  # noqa: ANN202
        if not _KEY.match(key):
            raise HTTPException(404, "no such report")
        rec = store.get(key)
        if rec is None:
            raise HTTPException(404, "no such report")
        return rec

    @app.get("/api/reports/{key}")
    def report(key: str, format: str = "json") -> Response:  # noqa: A002
        rec = _report(key)
        immutable = {"Cache-Control": "public, max-age=31536000, immutable"}
        if format == "json":
            return Response(rec.report_json, media_type="application/json", headers=immutable)
        if format not in _FORMATS:
            raise HTTPException(400, "format must be json, sarif, markdown, html or cyclonedx")
        mime, ext, render = _FORMATS[format]
        body = render(Report.model_validate_json(rec.report_json))
        headers = immutable | {"Content-Disposition": f'attachment; filename="agentguard-{key[:12]}.{ext}"'}
        if format == "html":
            # The report carries its own strict CSP; serve it as a download, scripts disabled.
            headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; sandbox"
        return Response(body, media_type=mime, headers=headers)

    @app.get("/api/reports/{key}/diff")
    def diff(key: str) -> dict:
        rec = _report(key)
        prev = store.previous(rec.kind, rec.locator, rec.scanned_at)
        if prev is None:
            return {"previous": None, "diff": None}
        d = diff_reports(Report.model_validate_json(prev.report_json), Report.model_validate_json(rec.report_json))
        return {"previous": {"key": prev.key, "resolved": prev.resolved, "scanned_at": prev.scanned_at.isoformat()},
                "diff": d.model_dump(mode="json")}

    return app


def _job_view(job: Job) -> dict:
    view = job.public()
    view["links"] = {"self": f"/api/scans/{job.id}", "events": f"/api/scans/{job.id}/events"}
    if job.report_key:
        view["links"]["report"] = f"/api/reports/{job.report_key}"
    return view
