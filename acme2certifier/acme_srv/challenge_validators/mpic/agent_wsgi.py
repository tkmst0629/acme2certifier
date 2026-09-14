# pylint: disable=E0401
"""
WSGI entry point for the MPIC remote agent.

Exposes ``POST {MPIC_VALIDATE_PATH}`` and answers corroboration requests from a
coordinator. Application-level authentication is a bearer token; mutual TLS is
expected to be terminated at the fronting reverse proxy (nginx/Apache), which
verifies the coordinator's client certificate and may pass its verification
result down as a header (checked when ``require_client_cert_header`` is set).

Configuration is read from the ``[MpicAgent]`` section of the acme2certifier
config file (or ``ACME_SRV_CONFIGFILE``):

    [MpicAgent]
    token: <shared secret presented as "Authorization: Bearer <token>">
    use_local_resolver: True
    require_client_cert_header: False

``token`` may also be supplied via the ``MPIC_AGENT_TOKEN`` environment
variable, which takes precedence.
"""

import hmac
import json
import os
from wsgiref.simple_server import make_server

from acme2certifier.acme_srv.helper import load_config, logger_setup
from .agent import build_agent
from .protocol import MPIC_VALIDATE_PATH

CONTENT_TYPE_JSON = "application/json"
_CLIENT_CERT_HEADER = "HTTP_X_SSL_CLIENT_VERIFY"


def _json_response(start_response, status: str, payload: dict):
    """Emit a JSON response body."""
    body = json.dumps(payload).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", CONTENT_TYPE_JSON),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


def _load_agent_config(logger):
    """Load [MpicAgent] configuration."""
    config = load_config(logger, "MpicAgent")
    cfg = config["MpicAgent"] if config.has_section("MpicAgent") else {}

    token = os.environ.get("MPIC_AGENT_TOKEN") or cfg.get("token")
    use_local_resolver = str(cfg.get("use_local_resolver", "True")).lower() in (
        "true",
        "yes",
        "1",
    )
    require_client_cert_header = str(
        cfg.get("require_client_cert_header", "False")
    ).lower() in ("true", "yes", "1")
    return token, use_local_resolver, require_client_cert_header


try:
    DEBUG = load_config().getboolean("DEFAULT", "debug", fallback=False)
except Exception:  # pragma: no cover - config edge cases
    DEBUG = False

LOGGER = logger_setup(DEBUG)
TOKEN, USE_LOCAL_RESOLVER, REQUIRE_CLIENT_CERT_HEADER = _load_agent_config(LOGGER)
AGENT = build_agent(LOGGER, use_local_resolver=USE_LOCAL_RESOLVER)

if not TOKEN:
    LOGGER.warning(
        "MPIC agent started without a token configured; every request will be "
        "rejected until [MpicAgent] token or MPIC_AGENT_TOKEN is set."
    )


def _authorized(environ) -> bool:
    """Check the bearer token (and optional client-cert header)."""
    if not TOKEN:
        return False
    header = environ.get("HTTP_AUTHORIZATION", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        return False
    presented = header[len(prefix) :]
    if not hmac.compare_digest(presented, TOKEN):
        return False
    if REQUIRE_CLIENT_CERT_HEADER and environ.get(_CLIENT_CERT_HEADER) != "SUCCESS":
        LOGGER.warning("MPIC agent: client certificate not verified by proxy")
        return False
    return True


def application(environ, start_response):
    """WSGI application for the MPIC remote agent."""
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "")

    if path != MPIC_VALIDATE_PATH:
        return _json_response(start_response, "404 Not Found", {"detail": "not found"})
    if method != "POST":
        return _json_response(
            start_response, "405 Method Not Allowed", {"detail": "expected POST"}
        )
    if not _authorized(environ):
        return _json_response(
            start_response, "401 Unauthorized", {"detail": "unauthorized"}
        )

    try:
        length = int(environ.get("CONTENT_LENGTH", 0) or 0)
        raw = environ["wsgi.input"].read(length) if length else b""
        payload = json.loads(raw.decode("utf-8")) if raw else {}
    except Exception as err:  # noqa: BLE001
        LOGGER.warning("MPIC agent: bad request body: %s", err)
        return _json_response(
            start_response, "400 Bad Request", {"detail": "invalid JSON body"}
        )

    result = AGENT.validate(payload)
    return _json_response(start_response, "200 OK", result)


def run(host: str = "0.0.0.0", port: int = 8443):  # pragma: no cover - dev runner
    """Run a development server. Use a real WSGI server + mTLS in production."""
    LOGGER.info("Starting MPIC agent dev server on %s:%d", host, port)
    with make_server(host, port, application) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    run()
