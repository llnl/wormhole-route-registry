"""Commands for Route Registry."""

import argparse
import logging
import os
import json
import sys
import tomli_w

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
import base64

from . import models
from .celery import make_celery_app, TaskProxy
from .clients.authorization import PikoAuthorizationClient
from .clients.holepunch import HolePunchClient
from .config import settings
from .server import make_server, generate_openapi_spec
from .service.uow import make_sql_uow
from .services import AlreadyExists, create_user
from .store.orm import make_engine
from .track import make_route_tracker
from .utils import get_local_username


def generate_openapi(args):
    generate_openapi_spec(settings.to_dict())


def generate_jwks(args):
    if not args.overwrite:
        if os.path.isdir("jwks"):
            print("jwks/ directory already exists! Set --overwrite to overwrite")
            sys.exit(1)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sha256 = hashlib.sha256(public_der).digest()
    kid = base64.urlsafe_b64encode(sha256).rstrip(b"=")

    Path("jwks").mkdir(exist_ok=True, parents=True)

    with open("jwks/private.pem", "wb") as f:
        f.write(private_pem)

    with open("jwks/public.pem", "wb") as f:
        f.write(public_pem)

    with open("jwks/kid.txt", "w") as f:
        f.write(kid.decode())

    if args.write_settings:
        filename = "settings.local.toml"
        if os.path.exists(filename):
            print(f"File {filename} already exists! Aborting.")
            sys.exit(1)

        data = {
            "dynaconf_merge": True,
            "default": {
                "auth": {
                    "jwt": {
                        "active_kid": "1",
                        "keys": {
                            "1": {
                                "key_type": "RSA",
                                "public_pem": public_pem.decode(),
                                "private_pem": private_pem.decode(),
                            }
                        },
                    },
                },
            },
        }

        with open(filename, "w") as fh:
            fh.write(tomli_w.dumps(data))


def seed_dev_user(args):
    """Create the local machine user so LocalDevAuthenticator can resolve it.

    Idempotent: safe to run on every dev-server start.
    """

    config = settings.to_dict()
    local_dev_config = config.get("AUTH", {}).get("local_dev", {})

    uid = args.uid or local_dev_config.get("uid") or get_local_username()
    if args.admin is None:
        is_admin = local_dev_config.get("is_admin", True)
    else:
        is_admin = args.admin

    UOW = make_sql_uow(make_engine(config.get("DB")))

    try:
        create_user(UOW, models.User(uid=uid, duid=uid, is_admin=is_admin))
        logging.info(f"Seeded dev user {uid!r} (is_admin={is_admin})")
        return
    except AlreadyExists:
        pass

    # Already present -- reconcile the admin flag so re-running with a
    # different --admin/--no-admin actually takes effect.
    with UOW() as uow:
        user = uow.entity_repo.get_user(uid)
        if user.is_admin == is_admin:
            logging.debug(f"Dev user {uid!r} already seeded (is_admin={is_admin})")
            return
        user.is_admin = is_admin

    logging.debug(f"Dev user {uid!r} updated (is_admin={is_admin})")


def listen_tasks(args):
    settings.CELERY.broker_url = args.broker_url or settings.CELERY.broker_url
    celery_app = make_celery_app(settings.to_dict())
    celery_worker = celery_app.Worker()
    try:
        celery_worker.start()
    except KeyboardInterrupt:
        print("Shutdown celery task worker")


def run_server(args):
    settings.SERVER.host = args.host or settings.SERVER.host
    settings.SERVER.port = args.port or settings.SERVER.port
    settings.log_level = args.log_level or settings.log_level

    logging.getLogger().setLevel(settings.log_level)

    config = settings.to_dict()

    engine = make_engine(config.get("DB"))
    UOW = make_sql_uow(engine)

    celery_app = make_celery_app(config)
    task_proxy = TaskProxy(celery_app)
    server = make_server(UOW, config, task_proxy)

    # Start trackers
    schema = json.loads(settings.SCHEMA.data)
    authz_client = PikoAuthorizationClient(config=config["URL"])
    holepunch_client = HolePunchClient(config=config["URL"]["holepunch"])
    make_route_tracker(
        UOW,
        schema,
        authz_client,
        holepunch_client,
        stale_duration=settings.TRACK.routes.stale_duration,
        check_interval=settings.TRACK.routes.check_interval,
    ).start()

    try:
        server.run()
    except KeyboardInterrupt:
        print("Shutdown server")


def cli():
    parser = argparse.ArgumentParser(description="Route Registry")
    subparser = parser.add_subparsers()

    task_parser = subparser.add_parser("listen-tasks")

    task_parser.add_argument(
        "--broker-url",
        help="""Set the broker url to queue tasks.""",
    )

    task_parser.set_defaults(func=listen_tasks)

    run_parser = subparser.add_parser("run")
    run_parser.add_argument(
        "--host",
        help="""Set the host to listen on.""",
    )
    run_parser.add_argument(
        "--port",
        type=int,
        help="""Set the port to listen on.""",
    )
    run_parser.add_argument(
        "--log-level",
        help="""Set the log level.""",
    )

    run_parser.set_defaults(func=run_server)

    seed_parser = subparser.add_parser(
        "seed-dev-user",
        help="""Seed the local machine user for local development.""",
    )
    seed_parser.add_argument(
        "--uid",
        help="""User to seed. Defaults to the local machine username if left blank.""",
    )
    seed_parser.add_argument(
        "--admin",
        dest="admin",
        action="store_true",
        default=None,
        help="""Seed the user as an admin. Defaults to auth.local_dev.is_admin.""",
    )
    seed_parser.add_argument(
        "--no-admin",
        dest="admin",
        action="store_false",
        help="""Seed the user without admin rights.""",
    )
    seed_parser.set_defaults(func=seed_dev_user)

    openapi_parser = subparser.add_parser("openapi")
    openapi_parser.set_defaults(func=generate_openapi)

    generate_jwks_parser = subparser.add_parser("generate-jwks")
    generate_jwks_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="""Allows overwriting an existing jwks directory""",
    )
    generate_jwks_parser.add_argument(
        "--write-settings",
        action="store_true",
        help="""Write a settings.local.toml file if it doesn't exist.""",
    )
    generate_jwks_parser.set_defaults(func=generate_jwks)

    args = parser.parse_args()
    args.func(args)
