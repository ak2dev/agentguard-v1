"""agentguard-web api | dispatcher | dev | prune | check-sandbox"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import subprocess
import sys

from .config import Settings
from .queue import make_queue
from .store import make_store


def _limiter(settings: Settings):  # noqa: ANN202
    from .ratelimit import MemoryRateLimiter, RedisRateLimiter

    if settings.queue.startswith(("redis://", "rediss://")):
        return RedisRateLimiter(settings.queue, settings.rate_per_minute, settings.rate_per_day)
    return MemoryRateLimiter(settings.rate_per_minute, settings.rate_per_day)


def check_sandbox(settings: Settings) -> int:
    """Prove the scanner sandbox cannot reach the network (run in CI and at deploy time)."""
    from .sandbox import DockerSandbox

    sb = DockerSandbox(settings.scanner_image, runtime=settings.docker_runtime)
    argv = sb.argv("agw-egress-check")
    argv[argv.index(settings.scanner_image):] = [
        "--entrypoint", "python", settings.scanner_image, "-c",
        "import socket,sys\n"
        "for host,port in (('1.1.1.1',443),('8.8.8.8',53),('registry.npmjs.org',443)):\n"
        "    try:\n"
        "        socket.create_connection((host,port),3); print('REACHED',host); sys.exit(1)\n"
        "    except OSError: pass\n"
        "print('NO-EGRESS')",
    ]
    proc = subprocess.run(argv, capture_output=True, timeout=60, check=False)  # noqa: S603
    out = proc.stdout.decode(errors="replace").strip()
    print(out or proc.stderr.decode(errors="replace").strip())
    return 0 if proc.returncode == 0 and out.endswith("NO-EGRESS") else 1


def run_dev(settings: Settings, store, host: str, port: int) -> int:  # noqa: ANN001
    """One process: the API plus a dispatcher thread sharing an in-memory queue."""
    import threading

    import uvicorn

    from .api import create_app
    from .dispatcher import run
    from .queue import MemoryQueue

    if settings.mode == "prod":
        print("`dev` is refused in production (AGW_MODE=prod)", file=sys.stderr)
        return 2
    if settings.sandbox == "inprocess":
        logging.getLogger("agentguard_web").warning("AGW_SANDBOX=inprocess: scans run WITHOUT isolation (development only)")
    queue = MemoryQueue()
    stop = threading.Event()
    worker = threading.Thread(target=run, args=(settings, queue, store, stop), name="agw-dispatcher", daemon=True)
    worker.start()
    app = create_app(settings, queue=queue, store=store, limiter=_limiter(settings))
    try:
        uvicorn.run(app, host=host, port=port, server_header=False)
    finally:
        stop.set()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentguard-web")
    sub = ap.add_subparsers(dest="cmd", required=True)
    api = sub.add_parser("api", help="serve the HTTP API")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
    sub.add_parser("dispatcher", help="resolve, fetch and scan queued jobs")
    dev = sub.add_parser("dev", help="API and dispatcher in one process with an in-memory queue (development only)")
    dev.add_argument("--host", default="127.0.0.1")
    dev.add_argument("--port", type=int, default=8000)
    sub.add_parser("prune", help="delete reports older than AGW_RETENTION_DAYS")
    sub.add_parser("check-sandbox", help="verify the scanner sandbox has no network egress")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.from_env()

    if args.cmd == "check-sandbox":
        return check_sandbox(settings)
    store = make_store(settings.store)
    if args.cmd == "prune":
        n = store.prune(dt.datetime.now(dt.UTC) - dt.timedelta(days=settings.retention_days))
        print(f"pruned {n} report(s) older than {settings.retention_days} days")
        return 0
    if args.cmd == "dev":
        return run_dev(settings, store, args.host, args.port)
    queue = make_queue(settings.queue)
    if args.cmd == "api":
        import uvicorn

        from .api import create_app

        app = create_app(settings, queue=queue, store=store, limiter=_limiter(settings))
        uvicorn.run(app, host=args.host, port=args.port, proxy_headers=settings.trust_proxy,
                    forwarded_allow_ips="*" if settings.trust_proxy else None, server_header=False)
        return 0
    if args.cmd == "dispatcher":
        if settings.queue == "memory":
            print("the dispatcher needs a shared queue (AGW_QUEUE=redis://...)", file=sys.stderr)
            return 2
        from .dispatcher import run

        run(settings, queue, store)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
