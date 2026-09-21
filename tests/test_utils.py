from route_registry.utils import get_local_username


def test_get_local_username_returns_the_current_account():
    assert get_local_username()


def test_local_username_honors_the_environment(monkeypatch):
    """Documented escape hatch: exporting LOGNAME lets a developer act as
    another seeded user, for both `seed-dev-user` and LocalDevAuthenticator.
    """

    monkeypatch.setenv("LOGNAME", "someone_else")

    assert get_local_username() == "someone_else"
