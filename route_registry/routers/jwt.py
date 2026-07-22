from fastapi import APIRouter, Depends
from typing import Annotated

from ..celery import TaskProxy
from ..dependencies import JWTAuthenticator
from ..models import Status
from ..services import create_piko_jwt


def make_router(jwt_auth: JWTAuthenticator, task_proxy: TaskProxy, url_config: dict):
    router = APIRouter(prefix="/jwt")
    authz_path = url_config["authorization_path"]

    @router.post("")
    async def _jwt(route: Annotated[str, Depends(jwt_auth)]) -> dict:
        if route.status is Status.DOWN:
            task_proxy.update_route.delay(route.id, authz_path)

        return {"jwt": create_piko_jwt(route, jwt_auth.jwt_config)}

    return router
