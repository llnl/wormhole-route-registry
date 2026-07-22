import pytest
from jsonschema import validate


def is_str(s) -> bool:
    return isinstance(s, str)


def are_strs(str_list: list) -> bool:
    return all(is_str(_) for _ in str_list)


valid_cases = [
    {},
    {"users": []},
    {"groups": []},
    {"users": ["user1"]},
    {"groups": ["group1"]},
    {"users": [], "groups": []},
    {"users": ["user1"], "groups": ["group1"]},
    {"users": ["user1"], "groups": []},
    {"users": [], "groups": ["group1"]},
]

invalid_cases = [
    {"users": [1]},
    {"groups": [1]},
    {"users": [1], "groups": [1]},
    {"users": [1], "groups": []},
    {"users": [], "groups": [1]},
    {"users": ["user1"], "groups": [1]},
    {"users": [1], "groups": ["group1"]},
    {"users": [{"user1"}], "groups": ["group1"]},
    {"users": ["user1"], "groups": [{"group1"}]},
    {"users": [True], "groups": ["group1"]},
    {"users": ["user1"], "groups": [True]},
]


@pytest.mark.parametrize("version", ["", "v0.0.0"])
@pytest.mark.parametrize("allowed", valid_cases + invalid_cases)
@pytest.mark.parametrize("disallowed", valid_cases + invalid_cases)
def test_schema_validation(version, allowed, disallowed, authorization_schema):
    # Setup
    data = {"version": version, "allowed": allowed, "disallowed": disallowed}

    should_succeed = version and all(
        are_strs(obj[k])
        for k in ["users", "groups"]
        for obj in [allowed, disallowed]
        if k in obj
    )

    # Execute/Verify
    if should_succeed:
        validate(instance=data, schema=authorization_schema)
    else:
        with pytest.raises(Exception):
            validate(instance=data, schema=authorization_schema)
