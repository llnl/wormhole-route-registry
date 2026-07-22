from fastapi import APIRouter, Depends, HTTPException, status
from typing import Annotated

from ..adapter import from_route
from ..dependencies import TokenOrFallbackAuthenticator
from ..celery import TaskProxy
from ..pydantic_models import (
    Route as PydanticRoute,
    RegistrationRequest,
    RegistrationResponse,
    Airlock,
    Tunnel,
)
from ..service.uow import BaseUOW
from ..services import (
    create_piko_jwt,
    get_user_community,
    list_available_routes,
    register_route,
    NotAllowed,
    NotFound,
    AlreadyExists,
)
from ..models import JWTConfig, User


def make_router(
    uow: BaseUOW,
    task_proxy: TaskProxy,
    jwt_config: JWTConfig,
    url_config: dict,
    auth: TokenOrFallbackAuthenticator,
):
    router = APIRouter(prefix="/route")
    authz_path = url_config["authorization_path"]
    bind_subdomain = url_config.get("bind_subdomain", True)
    tunnel_url = url_config["tunnel"]["base_url"]
    tunnel_connect_url = url_config["tunnel"]["connect_url"]
    token_service_url = url_config["token_service"]["base_url"]

    @router.get("")
    async def list_available() -> list[PydanticRoute]:
        routes = list_available_routes(uow)
        return [from_route(rt) for rt in routes]

    @router.post("")
    async def register(
        user: Annotated[User, Depends(auth.token_auth)],
        route_data: RegistrationRequest,
    ) -> RegistrationResponse:
        try:
            community = None
            if route_data.community_name:
                community = get_user_community(uow, user, route_data.community_name)
                if not community:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Community {route_data.community_name} does not exist",
                    )

            route = register_route(
                uow,
                user.uid,
                route_data.name,
                route_data.domain_name,
                tunnel_url,
                bind_subdomain,
                community=community,
            )
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.msg)
        except NotAllowed as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e.msg)

        task_proxy.update_route.delay(route.id, authz_path)
        task_proxy.notify_route_table_update.delay()

        jwt = create_piko_jwt(route, jwt_config)
        return RegistrationResponse(
            url=route.src,
            airlock=Airlock(jwt_issuer_url=token_service_url),
            tunnel=Tunnel(
                url=tunnel_connect_url,
                jwt=jwt,
                endpoint=route.id,
            ),
            # TODO: remove once client migrated
            jwt=jwt,
            endpoint=route.id,
        )

    @router.get("/hello-world")
    async def hello(user: Annotated[User, Depends(auth)]):
        print(f"Hello authenticated user: {user.uid}")

    return router
