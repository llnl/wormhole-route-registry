from flask import Flask


def fake_target(*args, **kwargs):
    raise NotImplementedError("Implement via mock")


app = Flask(__name__)


def make_fake_holepunch(config: dict):
    @app.post(f"/api/{config['version']}/webhook/routes")
    def route_webhook():
        return fake_target()

    return app
