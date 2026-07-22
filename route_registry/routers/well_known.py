from fastapi import APIRouter, status

from ..pydantic_models import JWKSet
from ..models import JWKS


def make_router(jwks: JWKS):
    router = APIRouter(
        prefix="/.well-known",
        tags=["well-known"],
    )

    @router.get("/jwks.json", status_code=status.HTTP_200_OK)
    async def _jwks() -> JWKSet:
        return jwks.keys

    return router
