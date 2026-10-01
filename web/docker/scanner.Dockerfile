# Agent Guard Web scanner sandbox image.
# Runs one scan per container: job spec + archive on stdin, report JSON on stdout.
# Started by the dispatcher with --network none, --read-only, a non-root user and
# all capabilities dropped (see web/src/agentguard_web/sandbox.py). Contains only
# the Agent Guard engine; it never executes scanned code.
# Build from the repository root:  docker build -f web/docker/scanner.Dockerfile -t agentguard-scanner:local .
FROM python:3.12-slim-bookworm AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m pip install "uv==0.12.19"
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY web/pyproject.toml web/pyproject.toml
COPY src src
COPY rules rules
COPY mappings mappings
COPY schemas schemas
COPY intel intel
# Exactly the locked dependency set of the engine, with hashes; then the engine itself.
RUN uv export --frozen --no-dev --no-emit-workspace --package agentguard -o /tmp/requirements.txt \
 && python -m pip install --require-hashes -r /tmp/requirements.txt --target /opt/agentguard \
 && python -m pip install --no-deps . --target /opt/agentguard

FROM python:3.12-slim-bookworm
ENV PYTHONPATH=/opt/agentguard PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/nonexistent
COPY --from=build /opt/agentguard /opt/agentguard
RUN python -m compileall -q /opt/agentguard \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
USER 65534:65534
ENTRYPOINT ["python", "-m", "agentguard.sandbox_entry"]
