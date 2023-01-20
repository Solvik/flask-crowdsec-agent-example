import os

from flask import Flask
from flask import request

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from crowdsec_agent import CrowdsecAgent

app = Flask(__name__)

CS_LAPI_URL = os.getenv("CS_LAPI_URL", "http://localhost:8081")
CS_LAPI_TOKEN = os.getenv("CS_LAPI_TOKEN")
cs_agent = CrowdsecAgent(CS_LAPI_URL, "flask_app", CS_LAPI_TOKEN)


def on_rate_limit(req):
    ip = request.remote_addr
    cs_agent.push_alert(
        ip, scenario="credit-card-stuffing", message=f"Rate limit breached for {ip}"
    )
    return


limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["2 per minute", "1 per second"],
    strategy="fixed-window",
    on_breach=on_rate_limit,
)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route("/pay")
@limiter.limit("1 per second")
def pay():
    return "<p>This page is rate limited to 1 query per second</p>"
