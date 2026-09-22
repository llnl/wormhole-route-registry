.PHONY: sync-dev sync-prod lock lock-check build test run-dev listen-tasks \
        jwks migrate openapi seed

.NOTPARALLEL:

HOST ?= localhost
PORT ?= 5001

# Authenticator used by run-dev. local_dev resolves every request to the seeded
# local user and requires no external identity provider. LOCAL DEVELOPMENT ONLY.
AUTH_NAME ?= local_dev

sync-dev:
	uv sync --dev

sync-prod:
	uv sync --frozen --no-dev

lock-check:
	uv lock --check

lock:
	uv lock

build:
	rm -rf dist/
	uv build --wheel

tests: sync-dev
	uvx tox run

test-no-e2e: sync-dev
	uvx tox -- -m "not e2e"

test-e2e: sync-dev
	uvx tox -- -m e2e

run-dev: seed
	DYNACONF_AUTH__auth_name=$(AUTH_NAME) \
	uv run wormhole_route_registry run --host $(HOST) --port $(PORT)

# find out command to run in production environment
#run-prod: sync-prod
#	uv run wormhole_route_registry run --host $(HOST) --port $(PORT)

# Celery worker. Needs a running RabbitMQ broker.
listen-tasks: sync-dev
	uv run wormhole_route_registry listen-tasks

generate-jwks:
	uv run wormhole_route_registry generate-jwks --write-settings --overwrite

migrate:
	uv run alembic upgrade head

openapi:
	uv run wormhole_route_registry openapi

seed: sync-dev
	uv run wormhole_route_registry seed-dev-user
