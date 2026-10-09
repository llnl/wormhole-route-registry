FROM python:3.11

WORKDIR /app

ARG project_version="0.1.3"

COPY pyproject.toml pyproject.toml
COPY uv.lock uv.lock
COPY alembic alembic
COPY scripts scripts
COPY route_registry/config/settings.toml settings.local.toml
RUN chgrp -R 0 /app && chmod -R g=u /app
RUN chmod -R g+x scripts

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies exactly as pinned in uv.lock; --locked fails the build
# if uv.lock is out of date with pyproject.toml
RUN --mount=from=ghcr.io/astral-sh/uv:0.12.23,source=/uv,target=/bin/uv \
    uv export --locked --no-dev --no-emit-project \
        --output-file /tmp/requirements.txt \
    && pip3 install --no-deps --requirement /tmp/requirements.txt \
    && pip3 install --no-deps wormhole-route-registry==$project_version \
    # OpenTelemetry is not in uv.lock
    && pip3 install opentelemetry-distro opentelemetry-exporter-otlp \
    # The opentelemetry-bootstrap -a install command reads through
    # active site-packages folder, and installs the corresponding instrumentation
    && opentelemetry-bootstrap -a install \
    # Restore any locked version OpenTelemetry changed; pip check then fails
    # if OpenTelemetry needs the changed version
    && pip3 install --no-deps --requirement /tmp/requirements.txt \
    && pip3 check \
    && rm /tmp/requirements.txt

ENTRYPOINT ["opentelemetry-instrument", "wormhole_route_registry"]
CMD ["run"]
