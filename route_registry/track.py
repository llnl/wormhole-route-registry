import logging
from attrs import define, field
from apscheduler.schedulers.background import BaseScheduler, BackgroundScheduler
from typing import Callable

from .clients.authorization import AuthorizationClient
from .clients.holepunch import HolePunchClient
from .service.uow import BaseUOW
from .services import (
    check_routes,
    notify_route_table_update,
)

logger = logging.getLogger(__name__)


@define
class Tracker:
    """Simple, base tracker."""

    config: dict = field()
    scheduler: BaseScheduler = field()

    @config.default
    def _config(self):
        return {}

    @scheduler.default
    def _scheduler(self):
        return BackgroundScheduler()

    def add_interval_job(self, job: Callable, check_interval: float = 60):
        """Add a job to the scheduler."""
        check_interval = self.config.get("check_interval", check_interval)
        self.scheduler.add_job(job, "interval", seconds=check_interval)

    def start(self):
        """Start tracking."""
        if self.scheduler.running:
            return

        self.scheduler.start()

    def stop(self):
        """Stop tracking the proxy."""
        if not self.scheduler.running:
            return

        self.scheduler.shutdown()


def make_check_routes(
    UOW: BaseUOW,
    schema: dict,
    authz_client: AuthorizationClient,
    holepunch_client: HolePunchClient,
    stale_duration: int = 300,
) -> Callable:
    """Make the callback to check route liveness."""

    def _fn():
        check_routes(UOW, schema, authz_client, stale_duration=stale_duration)
        notify_route_table_update(holepunch_client)

    return _fn


def make_route_tracker(
    UOW: BaseUOW,
    schema: dict,
    authz_client: AuthorizationClient,
    holepunch_client: HolePunchClient,
    stale_duration: int = 300,
    check_interval: float = 60,
    tracker_config: dict = None,
) -> Tracker:
    check = make_check_routes(
        UOW, schema, authz_client, holepunch_client, stale_duration=stale_duration
    )
    tracker_config = tracker_config or {}
    tracker = Tracker(config=tracker_config)
    tracker.add_interval_job(job=check, check_interval=check_interval)
    return tracker
