from fastapi import APIRouter, Depends

from route_registry import adapter
from route_registry.dependencies import (
    AdminTokenAuthenticator,
    require_admin_observer_role,
)
from route_registry.models import VerificationStatus, Status
from ..pydantic_models import Route as PydanticRoute
from ..service.uow import BaseUOW
from ..services import (
    list_routes,
)


def make_router(
    UOW: BaseUOW,
    admin_token_auth: AdminTokenAuthenticator,
):
    router = APIRouter(
        prefix="/admin/route",
        dependencies=[Depends(require_admin_observer_role(admin_token_auth))],
    )

    @router.get("")
    async def _list(
        verification_status: str = None, status: str = None
    ) -> list[PydanticRoute]:
        verification_status = adapter.to_verification_status(verification_status)
        status = adapter.to_status(status)

        return [
            adapter.from_route(route)
            for route in list_routes(UOW, verification_status, status)
        ]

    @router.get("/active")
    async def list_active() -> list[PydanticRoute]:
        return [
            adapter.from_route(route)
            for route in list_routes(UOW, VerificationStatus.VERIFIED, Status.UP)
        ]

    return router
