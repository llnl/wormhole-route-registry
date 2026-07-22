from fastapi import APIRouter, Depends, HTTPException, status
from typing import Annotated

from route_registry import adapter
from ..models import User
from route_registry.dependencies import (
    AdminTokenAuthenticator,
    require_admin,
    BaseUserAuthDependency,
    require_admin_identity_role,
)
from ..pydantic_models import User as PydanticUser
from ..service.uow import BaseUOW
from ..services import (
    create_user,
    remove_user,
    list_users,
    add_admin,
    remove_admin,
    NotFound,
    AlreadyExists,
)


def make_router(
    UOW: BaseUOW,
    user_auth: BaseUserAuthDependency,
    admin_token_auth: AdminTokenAuthenticator,
):
    router = APIRouter(
        prefix="/admin/users",
    )

    @router.get("", status_code=status.HTTP_200_OK)
    async def _list(
        _: Annotated[None, Depends(require_admin_identity_role(admin_token_auth))],
    ) -> list[PydanticUser]:
        return [adapter.from_user(user) for user in list_users(UOW)]

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def create(
        _: Annotated[None, Depends(require_admin_identity_role(admin_token_auth))],
        p_user: PydanticUser,
    ) -> PydanticUser:
        user = adapter.to_user(p_user)
        try:
            return adapter.from_user(create_user(UOW, user))
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.msg)

    @router.delete("/{uid}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete(
        _: Annotated[None, Depends(require_admin_identity_role(admin_token_auth))],
        uid: str,
    ):
        try:
            remove_user(UOW, uid)
        except NotFound:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return

    @router.put("/{user_uid}/admin", status_code=status.HTTP_204_NO_CONTENT)
    async def grant_admin_role(
        user: Annotated[User, Depends(require_admin(user_auth))], user_uid: str
    ):
        try:
            add_admin(UOW, user_uid)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        return

    @router.delete("/{user_uid}/admin", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_admin_role(
        user: Annotated[User, Depends(require_admin(user_auth))], user_uid: str
    ):
        try:
            remove_admin(UOW, user_uid)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        return

    return router
