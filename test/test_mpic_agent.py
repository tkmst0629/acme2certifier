#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Unit tests for the MPIC remote agent (server side)."""

# pylint: disable=C0415, R0904, W0212
import io
import sys
import json
import logging
import unittest
from unittest.mock import Mock

sys.path.insert(0, ".")
sys.path.insert(1, "..")

from acme2certifier.acme_srv.challenge_validators.base import ValidationResult
from acme2certifier.acme_srv.challenge_validators.mpic import (
    MpicAgent,
    build_agent,
    MPIC_VALIDATE_PATH,
)
from acme2certifier.acme_srv.challenge_validators.mpic import agent_wsgi


class TestMpicAgent(unittest.TestCase):
    """MpicAgent.validate logic."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)
        self.registry = Mock()

    def _agent(self, use_local_resolver=True):
        return MpicAgent(
            self.logger,
            self.registry,
            eligible_types=["http-01", "dns-01", "tls-alpn-01"],
            use_local_resolver=use_local_resolver,
        )

    def test_001_valid_request_runs_validator(self):
        self.registry.validate_challenge.return_value = ValidationResult(
            success=True, invalid=False, details={"d": 1}
        )
        out = self._agent().validate(
            {
                "challenge_type": "dns-01",
                "context": {
                    "token": "t",
                    "jwk_thumbprint": "j",
                    "authorization_value": "example.com",
                },
            }
        )
        self.assertEqual(
            out,
            {
                "success": True,
                "invalid": False,
                "error_message": None,
                "details": {"d": 1},
            },
        )
        # registry called with the reconstructed context
        args, _ = self.registry.validate_challenge.call_args
        self.assertEqual(args[0], "dns-01")
        self.assertEqual(args[1].authorization_value, "example.com")

    def test_002_unsupported_type_rejected(self):
        out = self._agent().validate(
            {"challenge_type": "email-reply-00", "context": {}}
        )
        self.assertFalse(out["success"])
        self.assertTrue(out["invalid"])
        self.assertIn("unsupported challenge_type", out["error_message"])
        self.registry.validate_challenge.assert_not_called()

    def test_003_missing_type_rejected(self):
        out = self._agent().validate({})
        self.assertFalse(out["success"])
        self.assertTrue(out["invalid"])

    def test_004_local_resolver_strips_forwarded_dns(self):
        self.registry.validate_challenge.return_value = ValidationResult(True, False)
        self._agent(use_local_resolver=True).validate(
            {
                "challenge_type": "dns-01",
                "context": {
                    "authorization_value": "example.com",
                    "dns_servers": ["9.9.9.9"],
                    "proxy_servers": {"http": "p"},
                },
            }
        )
        args, _ = self.registry.validate_challenge.call_args
        self.assertIsNone(args[1].dns_servers)
        self.assertIsNone(args[1].proxy_servers)

    def test_005_forwarded_dns_kept_when_configured(self):
        self.registry.validate_challenge.return_value = ValidationResult(True, False)
        self._agent(use_local_resolver=False).validate(
            {
                "challenge_type": "dns-01",
                "context": {
                    "authorization_value": "example.com",
                    "dns_servers": ["9.9.9.9"],
                },
            }
        )
        args, _ = self.registry.validate_challenge.call_args
        self.assertEqual(args[1].dns_servers, ["9.9.9.9"])

    def test_006_build_agent_registers_dcv_validators(self):
        agent = build_agent(self.logger)
        types = set(agent.registry.get_supported_types())
        self.assertEqual(types, {"http-01", "dns-01", "tls-alpn-01"})


class _StartResponse:
    """Capture WSGI start_response status/headers."""

    def __init__(self):
        self.status = None
        self.headers = None

    def __call__(self, status, headers):
        self.status = status
        self.headers = headers


def _environ(method="POST", path=MPIC_VALIDATE_PATH, body=b"", auth=None, extra=None):
    env = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    if auth is not None:
        env["HTTP_AUTHORIZATION"] = auth
    if extra:
        env.update(extra)
    return env


class TestAgentWsgi(unittest.TestCase):
    """agent_wsgi.application routing and auth."""

    def setUp(self):
        # override module globals for deterministic behaviour
        self._orig_token = agent_wsgi.TOKEN
        self._orig_agent = agent_wsgi.AGENT
        self._orig_require = agent_wsgi.REQUIRE_CLIENT_CERT_HEADER
        agent_wsgi.TOKEN = "secret"
        agent_wsgi.REQUIRE_CLIENT_CERT_HEADER = False
        agent_wsgi.AGENT = Mock()
        agent_wsgi.AGENT.validate.return_value = {
            "success": True,
            "invalid": False,
            "error_message": None,
            "details": {},
        }

    def tearDown(self):
        agent_wsgi.TOKEN = self._orig_token
        agent_wsgi.AGENT = self._orig_agent
        agent_wsgi.REQUIRE_CLIENT_CERT_HEADER = self._orig_require

    def _call(self, environ):
        sr = _StartResponse()
        body = b"".join(agent_wsgi.application(environ, sr))
        return sr.status, json.loads(body.decode("utf-8"))

    def test_010_happy_path(self):
        body = json.dumps({"challenge_type": "dns-01", "context": {}}).encode()
        status, payload = self._call(_environ(body=body, auth="Bearer secret"))
        self.assertTrue(status.startswith("200"))
        self.assertTrue(payload["success"])
        agent_wsgi.AGENT.validate.assert_called_once()

    def test_011_wrong_path_404(self):
        status, _ = self._call(_environ(path="/nope", auth="Bearer secret"))
        self.assertTrue(status.startswith("404"))

    def test_012_wrong_method_405(self):
        status, _ = self._call(_environ(method="GET", auth="Bearer secret"))
        self.assertTrue(status.startswith("405"))

    def test_013_missing_token_401(self):
        status, _ = self._call(_environ(body=b"{}"))
        self.assertTrue(status.startswith("401"))

    def test_014_wrong_token_401(self):
        status, _ = self._call(_environ(body=b"{}", auth="Bearer nope"))
        self.assertTrue(status.startswith("401"))

    def test_015_bad_json_400(self):
        status, _ = self._call(_environ(body=b"{not json", auth="Bearer secret"))
        self.assertTrue(status.startswith("400"))

    def test_016_no_token_configured_rejects(self):
        agent_wsgi.TOKEN = None
        status, _ = self._call(_environ(body=b"{}", auth="Bearer secret"))
        self.assertTrue(status.startswith("401"))

    def test_017_client_cert_header_required(self):
        agent_wsgi.REQUIRE_CLIENT_CERT_HEADER = True
        body = json.dumps({"challenge_type": "dns-01", "context": {}}).encode()
        # without the header -> 401
        status, _ = self._call(_environ(body=body, auth="Bearer secret"))
        self.assertTrue(status.startswith("401"))
        # with the header -> 200
        status, _ = self._call(
            _environ(
                body=body,
                auth="Bearer secret",
                extra={"HTTP_X_SSL_CLIENT_VERIFY": "SUCCESS"},
            )
        )
        self.assertTrue(status.startswith("200"))


if __name__ == "__main__":
    unittest.main()
