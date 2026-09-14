#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Unit tests for multi-perspective CAA corroboration (PR6)."""

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
    CaaChecker,
    CaaCorroborator,
    caa_permits,
    MpicCoordinator,
    QuorumPolicy,
    EnforcementMode,
    ExternalMpicProvider,
    RemotePerspective,
    PerspectiveResult,
    PerspectiveMetadata,
    build_agent,
)
from acme2certifier.acme_srv.challenge_validators.mpic.caa import CAA_CHECK_TYPE

_CAA_RRSET = (
    "acme2certifier.acme_srv.challenge_validators.mpic.caa_checker.caa_rrset_get"
)


def _issue(domain, tag="issue", flags=0):
    return {"flags": flags, "tag": tag, "value": domain}


class TestCaaPermits(unittest.TestCase):
    """caa_permits policy logic (RFC 8659 / 8657)."""

    def test_001_no_records_permits(self):
        self.assertTrue(caa_permits([], ["ca.example"]))

    def test_002_matching_issuer_permits(self):
        self.assertTrue(caa_permits([_issue("ca.example")], ["ca.example"]))

    def test_003_non_matching_issuer_forbids(self):
        self.assertFalse(caa_permits([_issue("other.example")], ["ca.example"]))

    def test_004_semicolon_forbids_all(self):
        self.assertFalse(caa_permits([_issue("")], ["ca.example"]))

    def test_005_only_iodef_permits(self):
        self.assertTrue(
            caa_permits([_issue("mailto:x@e", tag="iodef")], ["ca.example"])
        )

    def test_006_wildcard_uses_issuewild(self):
        records = [_issue("other.example", "issue"), _issue("ca.example", "issuewild")]
        self.assertTrue(caa_permits(records, ["ca.example"], is_wildcard=True))
        # non-wildcard uses issue -> forbidden here
        self.assertFalse(caa_permits(records, ["ca.example"], is_wildcard=False))

    def test_007_wildcard_falls_back_to_issue(self):
        records = [_issue("ca.example", "issue")]
        self.assertTrue(caa_permits(records, ["ca.example"], is_wildcard=True))

    def test_008_critical_unknown_forbids(self):
        records = [_issue("ca.example"), {"flags": 0x80, "tag": "weird", "value": "x"}]
        self.assertFalse(caa_permits(records, ["ca.example"]))

    def test_009_accounturi_match(self):
        rec = [_issue("ca.example; accounturi=https://a/acct/1")]
        self.assertTrue(
            caa_permits(rec, ["ca.example"], account_uri="https://a/acct/1")
        )
        self.assertFalse(
            caa_permits(rec, ["ca.example"], account_uri="https://a/acct/2")
        )

    def test_010_validationmethods(self):
        rec = [_issue("ca.example; validationmethods=dns-01,http-01")]
        self.assertTrue(caa_permits(rec, ["ca.example"], validation_method="dns-01"))
        self.assertFalse(
            caa_permits(rec, ["ca.example"], validation_method="tls-alpn-01")
        )


class TestCaaChecker(unittest.TestCase):
    """CaaChecker.perform_validation."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _ctx(self, value="www.example.com", issuers=("ca.example",)):
        return ChallengeContext(
            challenge_name="caa",
            token="",
            jwk_thumbprint="",
            authorization_type="dns",
            authorization_value=value,
            options={"issuer_domain_names": list(issuers)},
        )

    @patch(_CAA_RRSET)
    def test_020_permitted(self, mock_rrset):
        mock_rrset.return_value = ([_issue("ca.example")], False)
        res = CaaChecker(self.logger).perform_validation(self._ctx())
        self.assertTrue(res.success)
        self.assertFalse(res.invalid)

    @patch(_CAA_RRSET)
    def test_021_forbidden(self, mock_rrset):
        mock_rrset.return_value = ([_issue("other.example")], False)
        res = CaaChecker(self.logger).perform_validation(self._ctx())
        self.assertFalse(res.success)
        self.assertIn("caa", res.error_message)

    @patch(_CAA_RRSET)
    def test_022_lookup_error_fails_closed(self, mock_rrset):
        mock_rrset.return_value = (None, True)
        res = CaaChecker(self.logger).perform_validation(self._ctx())
        self.assertFalse(res.success)
        self.assertTrue(res.invalid)
        self.assertTrue(res.details["caa_error"])

    @patch(_CAA_RRSET)
    def test_023_wildcard_stripped_before_lookup(self, mock_rrset):
        mock_rrset.return_value = ([], False)
        CaaChecker(self.logger).perform_validation(self._ctx(value="*.example.com"))
        args, _ = mock_rrset.call_args
        self.assertEqual(args[1], "example.com")


class _FakeRemoteCaa(RemotePerspective):
    def __init__(self, logger, name, ok, country=None):
        super().__init__(
            logger, PerspectiveMetadata(name=name, country=country), is_primary=False
        )
        self._ok = ok

    def validate(self, challenge_type, context):
        return self._timed(
            lambda: PerspectiveResult(
                self.name, False, self._ok, not self._ok, metadata=self.metadata
            )
        )


class TestCaaCorroborator(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_030_delegates_to_handler_with_caa_type(self):
        handler = Mock()
        handler.corroborate.return_value = ValidationResult(True, False)
        corr = CaaCorroborator(self.logger, handler)
        corr.corroborate("www.example.com", ["ca.example"], account_uri="uri")
        args, _ = handler.corroborate.call_args
        self.assertEqual(args[0], CAA_CHECK_TYPE)
        ctx = args[1]
        self.assertEqual(ctx.authorization_value, "www.example.com")
        self.assertEqual(ctx.options["issuer_domain_names"], ["ca.example"])
        self.assertEqual(ctx.options["accounturi"], "uri")

    def test_031_wildcard_prefix_added(self):
        handler = Mock()
        handler.corroborate.return_value = ValidationResult(True, False)
        CaaCorroborator(self.logger, handler).corroborate(
            "example.com", ["ca.example"], is_wildcard=True
        )
        ctx = handler.corroborate.call_args.args[1]
        self.assertEqual(ctx.authorization_value, "*.example.com")

    @patch(_CAA_RRSET)
    def test_032_end_to_end_via_coordinator(self, mock_rrset):
        mock_rrset.return_value = ([_issue("ca.example")], False)
        coord = MpicCoordinator(
            self.logger,
            QuorumPolicy(2, EnforcementMode.ENFORCE),
            remote_perspectives=[
                _FakeRemoteCaa(self.logger, "a", True, "US"),
                _FakeRemoteCaa(self.logger, "b", True, "DE"),
            ],
        )
        corr = CaaCorroborator(self.logger, coord)
        res = corr.corroborate("www.example.com", ["ca.example"])
        self.assertTrue(res.success)
        self.assertEqual(len(res.details["perspectives"]), 3)


class TestExternalProviderCaa(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    @patch(
        "acme2certifier.acme_srv.challenge_validators.mpic.external_provider.requests"
    )
    def test_040_caa_request_shape(self, mock_requests):
        class _Resp:
            status_code = 200

            def json(self):
                return {"is_valid": True}

            def raise_for_status(self):
                pass

        mock_requests.post.return_value = _Resp()
        provider = ExternalMpicProvider(
            self.logger, url="https://mpic.example", enforcement=EnforcementMode.ENFORCE
        )
        ctx = ChallengeContext(
            challenge_name="caa",
            token="",
            jwk_thumbprint="",
            authorization_type="dns",
            authorization_value="*.example.com",
            options={"issuer_domain_names": ["ca.example"]},
        )
        r = provider.corroborate("caa", ctx, CaaChecker(self.logger))
        self.assertTrue(r.success)
        body = mock_requests.post.call_args.kwargs["json"]
        self.assertEqual(body["check_type"], "caa")
        self.assertEqual(body["domain_or_ip_target"], "example.com")
        self.assertEqual(
            body["caa_check_parameters"]["certificate_type"], "tls-server-wildcard"
        )
        self.assertEqual(body["caa_check_parameters"]["caa_domains"], ["ca.example"])


class TestAgentServesCaa(unittest.TestCase):
    def test_050_agent_supports_caa(self):
        logger = Mock(spec=logging.Logger)
        agent = build_agent(logger)
        self.assertIn("caa", agent.eligible_types)
        self.assertIn("caa", agent.registry.get_supported_types())


if __name__ == "__main__":
    unittest.main()
