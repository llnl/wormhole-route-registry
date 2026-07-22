from route_registry.adapter import from_route
from route_registry.models import Status, VerificationStatus
from route_registry.services import list_available_routes


def test_from_route(UOW, a_persisted_route, a_persisted_rule):
    # Setup
    with UOW() as uow:
        route = uow.route_repo.get(a_persisted_route.id)
        route.status = Status.UP
        route.verification_status = VerificationStatus.VERIFIED

    routes = list_available_routes(UOW)
    route = next(r for r in routes if r.id == a_persisted_route.id)

    # Execute
    p_route = from_route(route)

    # Assert
    assert p_route
    assert p_route.src == route.src
    assert p_route.dst == route.dst
    assert a_persisted_rule.entity.uid in p_route.rules.disallowed.users
