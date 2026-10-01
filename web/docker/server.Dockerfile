# Agent Guard Web API and dispatcher image (same image, different command).
# The dispatcher also needs the Docker CLI to start scanner sandboxes.
# Build from the repository root:  docker build -f web/docker/server.Dockerfile -t agentguard-web:local .
FROM docker:27-cli AS dockercli

FROM python:3.12-slim-bookworm AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m pip install "uv==0.12.19"
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src src
COPY rules rules
COPY mappings mappings
COPY schemas schemas
COPY intel intel
COPY web/pyproject.toml web/README.md web/
COPY web/src web/src
RUN uv export --frozen --no-dev --no-emit-workspace --package agentguard-web -o /tmp/requirements.txt \
 && python -m pip install --require-hashes -r /tmp/requirements.txt --target /opt/agw \
 && python -m pip install --no-deps . ./web --target /opt/agw

FROM python:3.12-slim-bookworm
ENV PYTHONPATH=/opt/agw PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/agw/bin:$PATH
COPY --from=build /opt/agw /opt/agw
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin agw
USER 10001
EXPOSE 8000
ENTRYPOINT ["python", "-m", "agentguard_web.cli"]
CMD ["api", "--host", "0.0.0.0", "--port", "8000"]
