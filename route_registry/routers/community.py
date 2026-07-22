from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from typing import Annotated, Optional

from ..adapter import to_community, from_community, from_membership_request
from ..dependencies import TokenOrFallbackAuthenticator
from ..pydantic_models import (
    Community as PydanticCommunity,
    MembershipRequest as PydanticMembershipRequest,
)
from ..service.uow import BaseUOW
from ..services import (
    add_route_to_community,
    remove_route_from_community,
    get_user_community,
    create_community,
    list_communities,
    remove_user_community,
    AlreadyExists,
    NotFound,
)
from ..models import User


def make_router(
    uow: BaseUOW,
    auth: TokenOrFallbackAuthenticator,
):
    router = APIRouter(prefix="/community")

    @router.get("")
    async def _list(user: Annotated[User, Depends(auth)]) -> list[PydanticCommunity]:
        communities = list_communities(uow, entity_id=user.id)
        return [from_community(c) for c in communities]

    @router.get("/{id_or_name}")
    async def get(
        user: Annotated[User, Depends(auth)], id_or_name: str
    ) -> Optional[PydanticCommunity]:
        community = get_user_community(uow, user, id_or_name)
        return from_community(community) if community else None

    @router.post("")
    async def create(
        user: Annotated[User, Depends(auth)], p_community: PydanticCommunity
    ) -> PydanticCommunity:
        try:
            community = create_community(uow, user, to_community(p_community))
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e.msg)

        return from_community(community)

    @router.put("/{community_id}/route/{route_id}")
    async def add_route(
        user: Annotated[User, Depends(auth)],
        community_id: str,
        route_id: str,
    ) -> Optional[PydanticMembershipRequest]:
        try:
            membership_request = add_route_to_community(
                uow, user, route_id, community_id
            )
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e.msg)

        return (
            from_membership_request(membership_request)
            if membership_request
            else Response(status_code=status.HTTP_204_NO_CONTENT)
        )

    @router.delete(
        "/{community_id}/route/{route_id}", status_code=status.HTTP_204_NO_CONTENT
    )
    async def remove_from_community(
        user: Annotated[User, Depends(auth)],
        community_id: str,
        route_id: str,
    ):
        try:
            remove_route_from_community(uow, user, route_id, community_id)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)

    @router.delete("/{id_or_name}", status_code=status.HTTP_204_NO_CONTENT)
    async def remove(user: Annotated[User, Depends(auth)], id_or_name: str):
        remove_user_community(uow, user, id_or_name)

    return router
