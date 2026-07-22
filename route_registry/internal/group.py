from fastapi import APIRouter, Depends, HTTPException, status

from route_registry import adapter
from route_registry.dependencies import (
    AdminTokenAuthenticator,
    require_admin_identity_role,
)
from ..pydantic_models import Group as PydanticGroup
from ..service.uow import BaseUOW
from ..services import (
    create_group,
    remove_group,
    list_groups,
    NotFound,
    AlreadyExists,
)


def make_router(
    UOW: BaseUOW,
    admin_token_auth: AdminTokenAuthenticator,
):
    router = APIRouter(
        prefix="/admin/groups",
        dependencies=[Depends(require_admin_identity_role(admin_token_auth))],
    )

    @router.get("", status_code=status.HTTP_200_OK)
    async def _list() -> list[PydanticGroup]:
        return [adapter.from_group(group) for group in list_groups(UOW)]

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def create(p_group: PydanticGroup) -> PydanticGroup:
        group = adapter.to_group(p_group)
        try:
            return adapter.from_group(create_group(UOW, group))
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.msg)

    @router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete(name: str):
        try:
            remove_group(UOW, name)
        except NotFound:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return

    return router
