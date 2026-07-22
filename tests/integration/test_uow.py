import pytest


def test_add_a_user(UOW, make_user):
    # Setup
    user = make_user()

    # Execute
    with UOW() as uow:
        uow.entity_repo.add(user)

    # Verify
    with UOW() as uow:
        actual_user = uow.entity_repo.get(user.id)
        assert actual_user == user


def test_a_user_uid_must_be_unique(UOW, make_user):
    # Setup
    user = make_user()
    user2 = make_user(id=user.id)

    # Execute
    with UOW() as uow:
        uow.entity_repo.add(user)

    # Verify
    with pytest.raises(Exception):
        with UOW() as uow:
            uow.entity_repo.add(user2)


def test_add_a_group(UOW, make_group):
    # Setup
    group = make_group()

    # Execute
    with UOW() as uow:
        uow.entity_repo.add(group)

    # Verify
    with UOW() as uow:
        actual_group = uow.entity_repo.get(group.id)
        assert actual_group == group


def test_a_group_name_must_be_unique(UOW, make_group):
    # Setup
    group = make_group()
    group2 = make_group(id=group.id)

    # Execute
    with UOW() as uow:
        uow.entity_repo.add(group)

    # Verify
    with pytest.raises(Exception):
        with UOW() as uow:
            uow.entity_repo.add(group2)


def test_add_a_route(UOW, make_route, make_domain):
    # Setup
    route = make_route(domain=make_domain())

    # Execute
    with UOW() as uow:
        uow.route_repo.add(route)

    # Verify
    with UOW() as uow:
        actual_route = uow.route_repo.get(route.id)
        assert actual_route == route


def test_associate_an_entity_and_route_with_a_rule(
    UOW, make_user, make_route, make_rule, make_domain
):
    # Setup
    user = make_user()
    domain = make_domain()
    route = make_route(domain=domain)
    rule = make_rule(entity=user, route=route)

    # Execute
    with UOW() as uow:
        uow.rule_repo.add(rule)

    # Verify
    with UOW() as uow:
        actual_rule = uow.rule_repo.get(route.id, user.id)
        assert actual_rule
        assert actual_rule.route_id == rule.route.id
        assert actual_rule.entity_id == rule.entity.id


def test_a_rule_is_unique_for_a_route_and_entity(
    UOW, make_user, make_route, make_rule, make_domain
):
    # Setup
    user = make_user()
    domain = make_domain()
    route = make_route(domain=domain)
    rule = make_rule(entity=user, route=route)
    rule2 = make_rule(entity=user, route=route)
    # Execute
    with UOW() as uow:
        uow.rule_repo.add(rule)

    # Verify
    with pytest.raises(Exception):
        with UOW() as uow:
            uow.entity_repo.add(rule2)


def test_rules_can_be_listed_for_a_specific_route(
    UOW, make_user, make_route, make_rule, make_domain
):
    # Setup
    domain = make_domain()
    route = make_route(domain=domain)
    route2 = make_route(src="foo2", dst="bar2", domain=domain)
    users = [make_user(id=i, uid=f"user_{i}", duid=f"duid_{i}") for i in range(1, 4)]
    expected_route_rules = [make_rule(entity=user, route=route) for user in users]
    another_route_rule = make_rule(entity=users[0], route=route2)

    # Execute
    with UOW() as uow:
        for rule in expected_route_rules:
            uow.rule_repo.add(rule)
        uow.rule_repo.add(another_route_rule)

    # Verify
    with UOW() as uow:
        actual_route_rules = uow.rule_repo.list(route.id)
        all_rules = uow.rule_repo.list()
        assert len(actual_route_rules) == len(expected_route_rules)
        assert all_rules > actual_route_rules
        assert all(rule.route_id == route.id for rule in actual_route_rules)
