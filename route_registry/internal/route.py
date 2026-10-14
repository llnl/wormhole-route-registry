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
        verification_status: VerificationStatus = None,
        status: Status = None,
        name: str = None,
    ) -> list[PydanticRoute]:
        return [
            adapter.from_route(route)
            for route in list_routes(
                UOW,
                verification_status=verification_status,
                status=status,
                name=name,
            )
        ]

    # Keep for backwards compatability
    @router.get("/active")
    async def list_active() -> list[PydanticRoute]:
        return [
            adapter.from_route(route)
            for route in list_routes(UOW, VerificationStatus.VERIFIED, Status.UP)
        ]

    return router
