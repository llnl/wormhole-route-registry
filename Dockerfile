FROM python:3.11

WORKDIR /app

ARG project_version="0.1.3"

COPY pyproject.toml pyproject.toml
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

RUN pip3 install wormhole-route-registry==$project_version \
    && pip3 install opentelemetry-distro opentelemetry-exporter-otlp \
# The opentelemetry-bootstrap -a install command reads through
# active site-packages folder, and installs the corresponding instrumentation
    && opentelemetry-bootstrap -a install

ENTRYPOINT ["opentelemetry-instrument", "wormhole_route_registry"]
CMD ["run"]
