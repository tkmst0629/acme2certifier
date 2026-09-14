#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Unit tests for the external Open MPIC provider adapter (PR5, method 3b)."""

# pylint: disable=C0415, R0904, W0212
import sys
import logging
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")

from acme2certifier.acme_srv.challenge_validators.base import (
    ChallengeValidator,
    ChallengeContext,
    ValidationResult,
)
from acme2certifier.acme_srv.challenge_validators.mpic import (
    ExternalMpicProvider,
    EnforcementMode,
)


class _FakeValidator(ChallengeValidator):
    def __init__(self, logger, ok=True):
        super().__init__(logger)
        self._ok = ok

    def get_challenge_type(self):
        return "dns-01"

    def perform_validation(self, context):
        return ValidationResult(
            success=self._ok, invalid=not self._ok, details={"local": 1}
        )


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _ctx(value="example.com", ctype="dns-01"):
    return ChallengeContext(
        challenge_name="c1",
        token="tok",
        jwk_thumbprint="jwk",
        authorization_type="dns",
        authorization_value=value,
    )


_REQUESTS = (
    "acme2certifier.acme_srv.challenge_validators.mpic.external_provider.requests"
)


class TestExternalProviderEnforce(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _provider(self, **kw):
        return ExternalMpicProvider(
            self.logger,
            url="https://mpic.example",
            api_key="k",
            enforcement=EnforcementMode.ENFORCE,
            **kw,
        )

    @patch(_REQUESTS)
    def test_001_valid_allows(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse(
            {"is_valid": True, "perspectives": [1, 2, 3]}
        )
        r = self._provider().corroborate(
            "dns-01", _ctx(), _FakeValidator(self.logger, True)
        )
        self.assertTrue(r.success)
        self.assertFalse(r.invalid)
        self.assertEqual(r.details["mpic_provider"], "open_mpic")

    @patch(_REQUESTS)
    def test_002_invalid_denies(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse({"is_valid": False})
        r = self._provider().corroborate(
            "dns-01", _ctx(), _FakeValidator(self.logger, True)
        )
        self.assertFalse(r.success)
        self.assertIn("incorrectResponse", r.error_message)

    @patch(_REQUESTS)
    def test_003_transport_error_denies(self, mock_requests):
        mock_requests.post.side_effect = ConnectionError("refused")
        r = self._provider().corroborate(
            "dns-01", _ctx(), _FakeValidator(self.logger, True)
        )
        self.assertFalse(r.success)
        self.assertIn("refused", r.details["response"]["error"])

    @patch(_REQUESTS)
    def test_004_request_shape_dns01(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse({"is_valid": True})
        self._provider(perspective_count=6, quorum_count=5).corroborate(
            "dns-01", _ctx(), _FakeValidator(self.logger, True)
        )
        _, kwargs = mock_requests.post.call_args
        body = kwargs["json"]
        self.assertTrue(mock_requests.post.call_args.args[0].endswith("/mpic"))
        self.assertEqual(body["domain_or_ip_target"], "example.com")
        self.assertEqual(body["validation_method"], "acme-dns-01")
        self.assertIn("key_authorization_hash", body)
        self.assertEqual(body["orchestration_parameters"]["perspective_count"], 6)
        self.assertEqual(body["orchestration_parameters"]["quorum_count"], 5)
        self.assertEqual(kwargs["headers"]["x-api-key"], "k")

    @patch(_REQUESTS)
    def test_005_request_shape_http01(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse({"is_valid": True})
        self._provider().corroborate(
            "http-01", _ctx(ctype="http-01"), _FakeValidator(self.logger, True)
        )
        body = mock_requests.post.call_args.kwargs["json"]
        self.assertEqual(body["validation_method"], "acme-http-01")
        self.assertEqual(body["token"], "tok")
        self.assertEqual(body["key_authorization"], "tok.jwk")

    @patch(_REQUESTS)
    def test_006_wildcard_stripped(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse({"is_valid": True})
        self._provider().corroborate(
            "dns-01", _ctx(value="*.example.com"), _FakeValidator(self.logger, True)
        )
        body = mock_requests.post.call_args.kwargs["json"]
        self.assertEqual(body["domain_or_ip_target"], "example.com")

    @patch(_REQUESTS)
    def test_007_bearer_token_header(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse({"is_valid": True})
        ExternalMpicProvider(
            self.logger, url="https://mpic.example", token="bear"
        ).corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        headers = mock_requests.post.call_args.kwargs["headers"]
        self.assertEqual(headers["Authorization"], "Bearer bear")


class TestExternalProviderMonitor(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _provider(self):
        return ExternalMpicProvider(
            self.logger,
            url="https://mpic.example",
            enforcement=EnforcementMode.MONITOR,
        )

    @patch(_REQUESTS)
    def test_010_monitor_gates_on_local_success(self, mock_requests):
        # external says invalid, but monitor must not block -> local decides
        mock_requests.post.return_value = _FakeResponse({"is_valid": False})
        r = self._provider().corroborate(
            "dns-01", _ctx(), _FakeValidator(self.logger, True)
        )
        self.assertTrue(r.success)
        self.assertEqual(r.details["observed"]["is_valid"], False)
        self.assertEqual(r.details["local"], {"local": 1})

    @patch(_REQUESTS)
    def test_011_monitor_local_failure_denies(self, mock_requests):
        mock_requests.post.return_value = _FakeResponse({"is_valid": True})
        r = self._provider().corroborate(
            "dns-01", _ctx(), _FakeValidator(self.logger, False)
        )
        self.assertFalse(r.success)


class TestSetupWiring(unittest.TestCase):
    """create_challenge_validator_registry selects the provider."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    class _Cfg:
        def __init__(self, **kw):
            base = dict(
                dns_persist_01_support=False,
                email_identifier_support=False,
                tnauthlist_support=False,
                forward_address_check=False,
                reverse_address_check=False,
            )
            base.update(kw)
            for k, v in base.items():
                setattr(self, k, v)

    def test_020_open_mpic_provider_selected(self):
        from acme2certifier.acme_srv.challenge_registry_setup import (
            create_challenge_validator_registry,
        )

        reg = create_challenge_validator_registry(
            self.logger,
            self._Cfg(
                mpic_enabled=True,
                mpic_enforcement="enforce",
                mpic_provider="open_mpic",
                mpic_provider_url="https://mpic.example",
                mpic_provider_api_key="k",
            ),
        )
        self.assertIsInstance(reg._mpic_coordinator, ExternalMpicProvider)
        self.assertEqual(reg._mpic_coordinator.url, "https://mpic.example/mpic")

    def test_021_default_is_self_hosted(self):
        from acme2certifier.acme_srv.challenge_registry_setup import (
            create_challenge_validator_registry,
        )
        from acme2certifier.acme_srv.challenge_validators.mpic import MpicCoordinator

        reg = create_challenge_validator_registry(
            self.logger, self._Cfg(mpic_enabled=True)
        )
        self.assertIsInstance(reg._mpic_coordinator, MpicCoordinator)


if __name__ == "__main__":
    unittest.main()
