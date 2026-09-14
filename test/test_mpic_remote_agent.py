#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Unit tests for the MPIC remote-agent client and wire protocol."""

# pylint: disable=C0415, R0904, W0212
import sys
import logging
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")

from acme2certifier.acme_srv.challenge_validators.base import (
    ChallengeContext,
    ValidationResult,
)
from acme2certifier.acme_srv.challenge_validators.mpic import (
    RemoteAgentPerspective,
    build_remote_perspectives,
    PerspectiveMetadata,
    MPIC_VALIDATE_PATH,
    context_to_payload,
    payload_to_context,
    validation_result_to_payload,
    payload_to_validation_result,
)


def _ctx():
    return ChallengeContext(
        challenge_name="c1",
        token="tok",
        jwk_thumbprint="jwk",
        authorization_type="dns",
        authorization_value="example.com",
        options={"http01_block_private_ips": True},
    )


class _SetupConfig:
    """Lightweight config object for build_remote_perspectives."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestProtocol(unittest.TestCase):
    """Wire protocol (de)serialisation round-trips."""

    def test_001_context_round_trip(self):
        ctx = _ctx()
        payload = context_to_payload(ctx)
        # payload must be JSON-safe primitives
        self.assertEqual(payload["token"], "tok")
        self.assertEqual(payload["authorization_value"], "example.com")
        rebuilt = payload_to_context(payload)
        self.assertEqual(rebuilt.token, ctx.token)
        self.assertEqual(rebuilt.authorization_value, ctx.authorization_value)
        self.assertEqual(rebuilt.options, ctx.options)

    def test_002_context_defaults_when_missing(self):
        ctx = payload_to_context({})
        self.assertEqual(ctx.challenge_name, "")
        self.assertEqual(ctx.authorization_type, "dns")
        self.assertEqual(ctx.timeout, 10)  # dataclass default preserved

    def test_003_validation_result_round_trip(self):
        vr = ValidationResult(
            success=True, invalid=False, error_message=None, details={"x": 1}
        )
        payload = validation_result_to_payload(vr)
        self.assertEqual(
            payload,
            {
                "success": True,
                "invalid": False,
                "error_message": None,
                "details": {"x": 1},
            },
        )
        rebuilt = payload_to_validation_result(payload)
        self.assertTrue(rebuilt.success)
        self.assertFalse(rebuilt.invalid)
        self.assertEqual(rebuilt.details, {"x": 1})

    def test_004_validation_result_defaults(self):
        rebuilt = payload_to_validation_result({})
        self.assertFalse(rebuilt.success)
        self.assertTrue(rebuilt.invalid)


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class TestRemoteAgentPerspective(unittest.TestCase):
    """RemoteAgentPerspective HTTP behaviour (requests mocked)."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)
        self.meta = PerspectiveMetadata(
            name="tokyo", url="https://agent.example:8443", country="JP", asn="AS-x"
        )

    @patch("acme2certifier.acme_srv.challenge_validators.mpic.remote_agent.requests")
    def test_010_success_maps_to_perspective_result(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse(
            {
                "success": True,
                "invalid": False,
                "error_message": None,
                "details": {"r": 1},
            }
        )
        p = RemoteAgentPerspective(
            self.logger,
            self.meta,
            client_cert="/c.crt",
            client_key="/c.key",
            ca_bundle="/ca.pem",
            timeout=5,
        )
        res = p.validate("dns-01", _ctx())
        self.assertTrue(res.corroborates)
        self.assertFalse(res.is_primary)
        self.assertEqual(res.perspective_name, "tokyo")
        self.assertEqual(res.evidence, {"r": 1})
        self.assertIsNotNone(res.elapsed_ms)

        # verify the outgoing request
        _, kwargs = mock_requests.post.call_args
        args, _ = mock_requests.post.call_args
        self.assertTrue(args[0].endswith(MPIC_VALIDATE_PATH))
        self.assertEqual(kwargs["cert"], ("/c.crt", "/c.key"))
        self.assertEqual(kwargs["verify"], "/ca.pem")
        self.assertEqual(kwargs["timeout"], 5)
        self.assertEqual(kwargs["json"]["challenge_type"], "dns-01")
        self.assertEqual(
            kwargs["json"]["context"]["authorization_value"], "example.com"
        )

    @patch("acme2certifier.acme_srv.challenge_validators.mpic.remote_agent.requests")
    def test_011_failure_response_non_corroborating(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse(
            {"success": False, "invalid": True, "error_message": "nope", "details": {}}
        )
        p = RemoteAgentPerspective(self.logger, self.meta)
        res = p.validate("dns-01", _ctx())
        self.assertFalse(res.corroborates)
        self.assertTrue(res.invalid)

    @patch("acme2certifier.acme_srv.challenge_validators.mpic.remote_agent.requests")
    def test_012_http_error_isolated_as_non_corroboration(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse({}, status=502)
        p = RemoteAgentPerspective(self.logger, self.meta)
        res = p.validate("dns-01", _ctx())
        self.assertFalse(res.corroborates)
        self.assertTrue(res.invalid)
        self.assertIsNotNone(res.error_message)

    @patch("acme2certifier.acme_srv.challenge_validators.mpic.remote_agent.requests")
    def test_013_exception_isolated(self, mock_requests):
        mock_requests.post.side_effect = ConnectionError("refused")
        p = RemoteAgentPerspective(self.logger, self.meta)
        res = p.validate("dns-01", _ctx())
        self.assertFalse(res.corroborates)
        self.assertIn("refused", res.error_message)

    @patch("acme2certifier.acme_srv.challenge_validators.mpic.remote_agent.requests")
    def test_014_no_client_cert_means_none(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse(
            {"success": True, "invalid": False}
        )
        p = RemoteAgentPerspective(self.logger, self.meta)
        p.validate("dns-01", _ctx())
        _, kwargs = mock_requests.post.call_args
        self.assertIsNone(kwargs["cert"])
        self.assertTrue(kwargs["verify"])  # default True when no ca bundle


class TestBuildRemotePerspectives(unittest.TestCase):
    """build_remote_perspectives factory."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_020_builds_from_config(self):
        cfg = _SetupConfig(
            mpic_perspectives=[
                {"name": "a", "url": "https://a:8443", "country": "US"},
                {"name": "b", "url": "https://b:8443", "country": "DE", "asn": "AS-y"},
            ],
            mpic_client_cert="/c.crt",
            mpic_client_key="/c.key",
            mpic_ca_bundle="/ca.pem",
            mpic_perspective_timeout=8,
        )
        ps = build_remote_perspectives(self.logger, cfg)
        self.assertEqual(len(ps), 2)
        self.assertEqual(ps[0].name, "a")
        self.assertEqual(ps[1].metadata.asn, "AS-y")
        self.assertEqual(ps[0].timeout, 8)
        self.assertEqual(ps[0].client_cert, ("/c.crt", "/c.key"))
        self.assertEqual(ps[0].verify, "/ca.pem")

    def test_021_skips_entries_missing_name_or_url(self):
        cfg = _SetupConfig(
            mpic_perspectives=[
                {"name": "a"},  # no url
                {"url": "https://b:8443"},  # no name
                {"name": "c", "url": "https://c:8443"},
                "not-a-dict",
            ]
        )
        ps = build_remote_perspectives(self.logger, cfg)
        self.assertEqual([p.name for p in ps], ["c"])

    def test_022_empty_when_unset(self):
        self.assertEqual(build_remote_perspectives(self.logger, _SetupConfig()), [])


class TestSetupWiringWithPerspectives(unittest.TestCase):
    """create_challenge_validator_registry builds remote perspectives."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _base(self, **kwargs):
        base = dict(
            dns_persist_01_support=False,
            email_identifier_support=False,
            tnauthlist_support=False,
            forward_address_check=False,
            reverse_address_check=False,
        )
        base.update(kwargs)
        return _SetupConfig(**base)

    def test_030_coordinator_gets_remote_perspectives(self):
        from acme2certifier.acme_srv.challenge_registry_setup import (
            create_challenge_validator_registry,
        )

        cfg = self._base(
            mpic_enabled=True,
            mpic_enforcement="enforce",
            mpic_min_remote_perspectives=2,
            mpic_perspective_timeout=10,
            mpic_perspectives=[
                {"name": "a", "url": "https://a:8443"},
                {"name": "b", "url": "https://b:8443"},
                {"name": "c", "url": "https://c:8443"},
            ],
            mpic_client_cert=None,
            mpic_client_key=None,
            mpic_ca_bundle=None,
        )
        reg = create_challenge_validator_registry(self.logger, cfg)
        self.assertIsNotNone(reg._mpic_coordinator)
        self.assertEqual(len(reg._mpic_coordinator.remote_perspectives), 3)


if __name__ == "__main__":
    unittest.main()
