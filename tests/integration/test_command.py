import pytest

from argparse import Namespace
from unittest import mock

from route_registry import command
from route_registry.models import User
from route_registry.store.repository import NotFound


@pytest.fixture
def seed(engine, UOW):
    """Run `seed-dev-user` against the test database.

    The command builds its own engine from settings, so redirect that at the
    test engine and let the caller stub the AUTH.local_dev table.
    """

    def _fn(uid=None, admin=None, config_uid="", config_is_admin=True, username=None):
        settings_dict = {
            "DB": {},
            "AUTH": {"local_dev": {"uid": config_uid, "is_admin": config_is_admin}},
        }

        # Dynaconf resolves attributes dynamically, so patch the settings
        # object wholesale rather than one of its attributes.
        fake_settings = mock.Mock()
        fake_settings.to_dict.return_value = settings_dict

        with (
            mock.patch.object(command, "settings", fake_settings),
            mock.patch.object(command, "make_engine", return_value=engine),
            mock.patch.object(
                command, "local_username", return_value=username or "machine_user"
            ),
        ):
            command.seed_dev_user(Namespace(uid=uid, admin=admin))

    return _fn


@pytest.fixture
def get_seeded(UOW):
    def _fn(uid):
        with UOW() as uow:
            return uow.entity_repo.get_user(uid)

    return _fn


@pytest.fixture
def count_users(UOW):
    def _fn():
        with UOW() as uow:
            return len(uow.entity_repo.list(User))

    return _fn


def test_seeds_the_local_machine_user(seed, get_seeded):
    # Execute
    seed(username="machine_user")

    # Verify
    user = get_seeded("machine_user")
    assert user.uid == "machine_user"
    assert user.duid == "machine_user"


def test_seeds_as_admin_by_default(seed, get_seeded):
    """AUTH.local_dev.is_admin ships as true, so the dev user can reach /admin."""

    seed()

    assert get_seeded("machine_user").is_admin


def test_uid_argument_overrides_everything(seed, get_seeded):
    # Execute
    seed(uid="explicit_user", config_uid="config_user", username="machine_user")

    # Verify
    assert get_seeded("explicit_user")
    for shadowed in ("config_user", "machine_user"):
        with pytest.raises(NotFound):
            get_seeded(shadowed)


def test_config_uid_wins_over_the_machine_user(seed, get_seeded):
    seed(config_uid="config_user", username="machine_user")

    assert get_seeded("config_user")
    with pytest.raises(NotFound):
        get_seeded("machine_user")


def test_no_admin_flag_overrides_the_config_default(seed, get_seeded):
    seed(admin=False, config_is_admin=True)

    assert not get_seeded("machine_user").is_admin


def test_config_is_admin_false_is_respected(seed, get_seeded):
    seed(config_is_admin=False)

    assert not get_seeded("machine_user").is_admin


def test_is_idempotent(seed, get_seeded, count_users):
    """The Makefile runs this on every `make run-dev`."""

    # Execute
    seed()
    seed()

    # Verify
    assert count_users() == 1
    assert get_seeded("machine_user").is_admin


def test_reseeding_demotes_an_existing_admin(seed, get_seeded, count_users):
    # Setup
    seed(admin=True)
    assert get_seeded("machine_user").is_admin

    # Execute
    seed(admin=False)

    # Verify
    assert not get_seeded("machine_user").is_admin
    assert count_users() == 1


def test_reseeding_promotes_an_existing_non_admin(seed, get_seeded, count_users):
    # Setup
    seed(admin=False)
    assert not get_seeded("machine_user").is_admin

    # Execute
    seed(admin=True)

    # Verify
    assert get_seeded("machine_user").is_admin
    assert count_users() == 1


def test_seeding_a_second_user_leaves_the_first_alone(seed, get_seeded, count_users):
    """`--uid` is how a developer sets up a non-admin to test 403 paths."""

    seed(uid="first_user", admin=True)
    seed(uid="second_user", admin=False)

    assert get_seeded("first_user").is_admin
    assert not get_seeded("second_user").is_admin
    assert count_users() == 2


def test_the_cli_registers_the_subcommand():
    """Guards the argparse wiring: --uid/--admin/--no-admin and the default."""

    with mock.patch("sys.argv", ["wormhole_route_registry", "seed-dev-user"]):
        with mock.patch.object(command, "seed_dev_user") as seed_dev_user:
            command.cli()

    args = seed_dev_user.call_args.args[0]
    assert args.uid is None
    # None, not False -- that is what lets the config default apply
    assert args.admin is None


@pytest.mark.parametrize(
    "argv,expected_uid,expected_admin",
    [
        (["--uid", "someone"], "someone", None),
        (["--admin"], None, True),
        (["--no-admin"], None, False),
    ],
)
def test_the_cli_parses_the_flags(argv, expected_uid, expected_admin):
    with mock.patch("sys.argv", ["wormhole_route_registry", "seed-dev-user", *argv]):
        with mock.patch.object(command, "seed_dev_user") as seed_dev_user:
            command.cli()

    args = seed_dev_user.call_args.args[0]
    assert args.uid == expected_uid
    assert args.admin is expected_admin
