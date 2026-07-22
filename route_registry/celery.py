import json
from celery import Celery, Task
from celery.app import task

from typing import Callable

from .clients.authorization import PikoAuthorizationClient
from .clients.holepunch import HolePunchClient
from .services import (
    notify_route_table_update as _notify_route_table_update,
    update_route as _update_route,
)
from .store.orm import make_engine
from .service.uow import make_sql_uow
from urllib.parse import urlparse


class TaskProxy:
    """Makes all registered celery tasks directly callable."""

    def __init__(self, celery_app: Celery):
        def normalize_name(name: str) -> str:
            return name.split(".")[-1]

        tasks = {
            normalize_name(n): t
            for n, t in celery_app.tasks.items()
            if not n.startswith("celery.")
        }
        for task_name, t in tasks.items():
            setattr(self, task_name, t)


def make_failure_callback(method: Callable) -> Callable:
    def _fn(self, exc, task_id, args, kwargs, einfo=None):
        method()

    return _fn


def make_success_callback(method: Callable) -> Callable:
    def _fn(self, retval, task_id, args, kwargs):
        method()

    return _fn


def create_broker_url(config: dict):
    rabbit_conf = config["RABBITMQ"]
    username = rabbit_conf.get("username")
    password = rabbit_conf.get("password")

    if not (username and password):
        return config["CELERY"]["broker_url"]

    parsed = urlparse(config["CELERY"]["broker_url"])
    return f"{parsed.scheme}://{username}:{password}@{parsed.hostname}{parsed.path}"


def bind_tasks(app: Celery, config: dict):
    class ConfigAwareTask(Task):
        _name = "base"

        @property
        def db_config(self):
            return config["DB"]

        @property
        def schema(self):
            return json.loads(config["SCHEMA"]["data"])

        @property
        def task_config(self):
            return config["TASKS"].get(self._name, {})

        @property
        def authz_client(self):
            return PikoAuthorizationClient(config=config["URL"])

        @property
        def holepunch_client(self):
            return HolePunchClient(config=config["URL"]["holepunch"])

        @property
        def celery_config(self):
            return self.task_config.get("celery", {})

        @property
        def max_retries(self):
            return self.celery_config.get("max_retries", 5)

        @property
        def retry_backoff(self):
            return self.celery_config.get("retry_backoff", True)

    class UpdateTask(ConfigAwareTask):
        _name = "update_route"
        autoretry_for = (Exception,)

    class WebhookTask(ConfigAwareTask):
        _name = "webhook_task"
        autoretry_for = (Exception,)

    @app.task(base=UpdateTask, bind=True)
    def update_route(self: task, route_id: str, authz_path: str = ""):
        engine = make_engine(self.db_config)
        UOW = make_sql_uow(engine)

        _update_route(UOW, route_id, self.authz_client, self.schema)

    @app.task(base=WebhookTask, bind=True)
    def notify_route_table_update(self: task):
        _notify_route_table_update(self.holepunch_client)


def make_celery_app(config: dict) -> Celery:
    app = Celery("route_registry")
    celery_config = config["CELERY"]
    celery_config["broker_url"] = create_broker_url(config)

    app.conf.update(**celery_config)

    bind_tasks(app, config)

    return app
