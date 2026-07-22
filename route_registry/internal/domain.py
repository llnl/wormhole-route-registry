from fastapi import APIRouter, Depends, HTTPException, status

from route_registry import adapter
from route_registry.dependencies import (
    AdminTokenAuthenticator,
    require_admin_domain_role,
)
from ..pydantic_models import Domain as PydanticDomain
from ..service.uow import BaseUOW
from ..services import (
    create_domain,
    set_default_domain,
    list_domains,
    remove_domain,
    NotFound,
    AlreadyExists,
)


def make_router(
    UOW: BaseUOW,
    admin_token_auth: AdminTokenAuthenticator,
):
    router = APIRouter(
        prefix="/admin/domain",
        dependencies=[Depends(require_admin_domain_role(admin_token_auth))],
    )

    @router.get("", status_code=status.HTTP_200_OK)
    async def _list() -> list[PydanticDomain]:
        return [adapter.from_domain(domain) for domain in list_domains(UOW)]

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def create(p_domain: PydanticDomain) -> PydanticDomain:
        domain = adapter.to_domain(p_domain)
        try:
            return adapter.from_domain(create_domain(UOW, domain))
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.msg)

    @router.put("/default/{domain_id}", status_code=status.HTTP_202_ACCEPTED)
    async def make_default_domain(domain_id: str):
        try:
            set_default_domain(UOW, domain_id)
        except NotFound:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    @router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete(domain_id: str):
        try:
            remove_domain(UOW, domain_id)
        except NotFound:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    return router
