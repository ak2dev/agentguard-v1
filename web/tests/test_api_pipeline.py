"""End to end without network or Docker: API → queue → pipeline (in-process sandbox) → store → API."""

from __future__ import annotations

import json

import pytest
from conftest import FakeFetcher, npm_routes
from fastapi.testclient import TestClient

from agentguard.sandbox_entry import frame, run

from agentguard_web.api import create_app
from agentguard_web.config import Settings
from agentguard_web.pipeline import Pipeline
from agentguard_web.queue import MemoryQueue
from agentguard_web.ratelimit import MemoryRateLimiter
from agentguard_web.sandbox import DockerSandbox, InProcessSandbox, SandboxError
from agentguard_web.store import MemoryStore, SqliteStore


@pytest.fixture()
def env():
    settings = Settings(mode="dev", store="memory", queue="memory", sandbox="inprocess", queue_cap=3, pow_difficulty=0)
    queue, store = MemoryQueue(), MemoryStore()
    limiter = MemoryRateLimiter(per_minute=5, per_day=100)
    client = TestClient(create_app(settings, queue=queue, store=store, limiter=limiter))
    fetcher = FakeFetcher(npm_routes())
    pipeline = Pipeline(queue=queue, store=store, sandbox=InProcessSandbox(), fetcher=fetcher)
    return client, queue, store, pipeline, fetcher


def submit_and_run(client, pipeline, text="npm:pdf-helper-mcp@1.2.3"):
    r = client.post("/api/scans", json={"input": text})
    assert r.status_code == 202, r.text
    job_id = r.json()["id"]
    pipeline.process(pipeline.queue.next(0))
    return client.get(f"/api/scans/{job_id}").json()


def test_scan_npm_package_end_to_end(env):
    client, _, _, pipeline, _ = env
    job = submit_and_run(client, pipeline)
    assert job["status"] == "done" and not job["cached"], job
    rep = client.get(job["links"]["report"])
    assert rep.status_code == 200 and "immutable" in rep.headers["cache-control"]
    report = rep.json()
    assert report["target"]["kind"] == "npm" and report["target"]["resolved"] == "1.2.3"
    assert any(f["rule_id"].startswith("AG-SKL-SE-") for f in report["findings"])
    for fmt in ("sarif", "markdown", "html", "cyclonedx"):
        r = client.get(job["links"]["report"], params={"format": fmt})
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    html = client.get(job["links"]["report"], params={"format": "html"})
    assert "sandbox" in html.headers["content-security-policy"]


def test_second_scan_is_served_from_cache_and_identical(env):
    client, _, store, pipeline, fetcher = env
    first = submit_and_run(client, pipeline)
    downloads = sum(u.endswith(".tgz") for u in fetcher.requested)
    second = submit_and_run(client, pipeline)
    assert second["cached"] and second["report_key"] == first["report_key"]
    assert sum(u.endswith(".tgz") for u in fetcher.requested) == downloads  # not downloaded again
    assert store.get(first["report_key"]) is not None


def test_same_ref_same_pack_gives_identical_report(env, lure_tar):
    spec = {"source": {"kind": "npm", "locator": "x", "resolved": "1.0.0", "integrity": "sha512:00"}, "strip_components": 1}
    a = InProcessSandbox().run(lure_tar, spec, 30)
    b = InProcessSandbox().run(lure_tar, spec, 30)
    assert a == b and json.loads(a)["target"]["resolved"] == "1.0.0"


def test_bad_input_lists_supported(env):
    client = env[0]
    r = client.post("/api/scans", json={"input": "not a link"})
    assert r.status_code == 400 and len(r.json()["supported"]) >= 5


def test_rate_limit_and_queue_cap(env):
    client = env[0]
    codes = [client.post("/api/scans", json={"input": f"npm:pkg{i}@1.0.0"}).status_code for i in range(6)]
    assert codes[:3] == [202, 202, 202] and 503 in codes and 429 in codes  # cap 3, then 5/minute


def test_resolution_errors_reach_the_job(env):
    client, _, _, pipeline, _ = env
    job = submit_and_run(client, pipeline, "npm:no-such-package@1.0.0")
    assert job["status"] == "error" and "not found" in job["error"]


def test_tampered_tarball_is_rejected(env):
    client, _, _, pipeline, fetcher = env
    tar_url = next(u for u in fetcher.routes if u.endswith(".tgz"))
    fetcher.routes[tar_url] = fetcher.routes[tar_url] + b"tampered"
    job = submit_and_run(client, pipeline)
    assert job["status"] == "error" and "digest mismatch" in job["error"]


def test_unknown_ids_and_bad_keys(env):
    client = env[0]
    assert client.get("/api/scans/" + "0" * 24).status_code == 404
    assert client.get("/api/scans/../../etc").status_code == 404
    assert client.get("/api/reports/notakey").status_code == 404


def test_security_headers_and_body_cap(env):
    client = env[0]
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff" and "frame-ancestors 'none'" in r.headers["content-security-policy"]
    big = client.post("/api/scans", content=b"x" * 10000, headers={"content-type": "application/json"})
    assert big.status_code == 413


def test_events_stream_ends_when_done(env):
    client, _, _, pipeline, _ = env
    job = submit_and_run(client, pipeline)
    with client.stream("GET", f"/api/scans/{job['id']}/events") as s:
        events = [line for line in s.iter_lines() if line.startswith("data: ")]
    assert json.loads(events[-1][6:])["status"] == "done"


def test_diff_against_previous_scan(env):
    client, _, _, pipeline, fetcher = env
    first = submit_and_run(client, pipeline)
    assert client.get(f"/api/reports/{first['report_key']}/diff").json()["previous"] is None
    # publish a new version that drops the lure
    from conftest import tarball

    fetcher.routes.update(npm_routes(version="1.2.4", data=tarball({"SKILL.md": b"---\nname: pdf-helper\ndescription: Merge PDF files.\n---\nUse it.\n"})))
    fetcher.routes["https://registry.npmjs.org/pdf-helper-mcp"]["versions"].update(
        npm_routes()["https://registry.npmjs.org/pdf-helper-mcp"]["versions"])
    second = submit_and_run(client, pipeline, "npm:pdf-helper-mcp@1.2.4")
    d = client.get(f"/api/reports/{second['report_key']}/diff").json()
    assert d["previous"]["resolved"] == "1.2.3" and d["diff"]["removed"]


def test_sqlite_store_roundtrip(tmp_path):
    from agentguard_web.models import StoredReport, now

    s = SqliteStore(str(tmp_path / "r.db"))
    rec = StoredReport(key="a" * 32, kind="npm", locator="x", resolved="1", rule_pack_version="0.1.0",
                       engine_version="e", scanned_at=now(), report_json="{}")
    s.put(rec)
    s.put(rec)  # idempotent
    assert s.get("a" * 32).locator == "x" and s.get("b" * 32) is None


def test_sandbox_entry_rejects_bad_input():
    import io

    assert run(io.BytesIO(b"no newline"))[0] == 2
    assert run(io.BytesIO(b"{not json}\n"))[0] == 2
    code, out = run(io.BytesIO(frame({"source": {"kind": "npm", "locator": "x", "resolved": "1"}}, b"not an archive")))
    assert code == 2 and "error" in json.loads(out)
    with pytest.raises(SandboxError):
        InProcessSandbox().run(b"garbage", {"source": {"kind": "npm", "locator": "x", "resolved": "1"}}, 10)


def test_docker_sandbox_flags():
    argv = DockerSandbox("img:tag", runtime="runsc").argv("n")
    for flag in ("--network", "none", "--read-only", "--cap-drop", "ALL", "no-new-privileges",
                 "--pids-limit", "--memory", "--user", "65534:65534", "--runtime", "runsc"):
        assert flag in argv
    assert argv[-1] == "img:tag" and "-v" not in argv and "--volume" not in argv and "--privileged" not in argv


def test_production_refuses_unsafe_settings():
    with pytest.raises(ValueError):
        Settings(mode="prod", sandbox="inprocess", queue="redis://x").validate()
    with pytest.raises(ValueError):
        Settings(mode="prod", sandbox="docker", queue="memory").validate()
