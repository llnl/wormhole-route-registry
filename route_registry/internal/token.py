from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Annotated

from route_registry import adapter
from ..dependencies import (
    BaseUserAuthDependency,
    require_admin,
)
from ..pydantic_models import (
    AdminToken as PydanticAdminToken,
)
from ..models import User
from ..service.uow import BaseUOW
from ..services import (
    list_admin_tokens,
    remove_admin_token,
    create_admin_token,
    BaseServiceException,
    AlreadyExists,
    NotFound,
)


def make_router(
    UOW: BaseUOW,
    user_auth: BaseUserAuthDependency,
):
    router = APIRouter(
        prefix="/admin/token",
        tags=["admin-token"],
    )

    @router.post("", status_code=status.HTTP_201_CREATED, response_model=str)
    async def create(
        user: Annotated[User, Depends(require_admin(user_auth))],
        admin_token_data: PydanticAdminToken,
    ) -> str:
        admin_token = adapter.to_admin_token(admin_token_data)
        try:
            return create_admin_token(UOW, admin_token)
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e.msg)
        except BaseServiceException as e:
            # TODO add logging
            # log.error(f"failed creating admin token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
            )

    @router.get(
        "", status_code=status.HTTP_200_OK, response_model=List[PydanticAdminToken]
    )
    async def list_tokens(
        user: Annotated[User, Depends(require_admin(user_auth))],
    ) -> List[PydanticAdminToken]:
        return [
            adapter.from_admin_token(admin_token)
            for admin_token in list_admin_tokens(UOW)
        ]

    @router.delete("/{admin_token_value}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_by_value(
        user: Annotated[User, Depends(require_admin(user_auth))],
        admin_token_value: str,
    ):
        try:
            remove_admin_token(UOW, admin_token_value)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        return

    return router
