from flask import Flask, request


def fake_target(*args, **kwargs):
    raise NotImplementedError("Implement via mock")


def validate_request_target(rq):
    pass


app = Flask(__name__)


def make_fake_app(config: dict, route_name: str):
    # Serve both v1 and v2 authz paths with the same handler.
    # v1: /-/airlock/authz.json
    # v2: /<route_name>/-/airlock/authz.json
    @app.get(config["authorization_path"])  # v1 static path
    @app.get(f"/{route_name}{config['authorization_path']}")  # v2 per-route path
    def authz(route_name=None):  # route_name provided when hitting v2 path
        validate_request_target(request)
        return fake_target()

    return app
