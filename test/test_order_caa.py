#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Unit tests for the CAA check wired into order finalize (PR7)."""

# pylint: disable=C0415, R0904, W0212
import sys
import json
import logging
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")

from acme2certifier.acme_srv.challenge_validators.base import ValidationResult


def _order():
    """Build an Order instance without running __enter__/config load."""
    from acme2certifier.acme_srv.order import Order

    with patch("acme2certifier.acme_srv.order.DBstore"), patch(
        "acme2certifier.acme_srv.order.Message"
    ):
        order = Order(False, "http://acme.example", Mock(spec=logging.Logger))
    order.repository = Mock()
    return order


class TestCaaCheckGate(unittest.TestCase):
    """Order._caa_check behaviour."""

    def setUp(self):
        self.order = _order()
        self.order.config.mpic_caa_check = True
        self.order.config.caaidentities = ["ca.example"]
        self.order.caa_corroborator = Mock()
        self.order.caa_corroborator.corroborate.return_value = ValidationResult(
            True, False
        )
        self.order.repository.order_lookup.return_value = {
            "identifiers": json.dumps([{"type": "dns", "value": "www.example.com"}])
        }

    def test_001_disabled_is_noop(self):
        self.order.config.mpic_caa_check = False
        self.assertIsNone(self.order._caa_check("o1"))
        self.order.caa_corroborator.corroborate.assert_not_called()

    def test_002_permitted_returns_none(self):
        self.assertIsNone(self.order._caa_check("o1"))
        self.order.caa_corroborator.corroborate.assert_called_once()
        _, kwargs = self.order.caa_corroborator.corroborate.call_args
        self.assertEqual(kwargs["issuer_identities"], ["ca.example"])

    def test_003_forbidden_returns_detail(self):
        self.order.caa_corroborator.corroborate.return_value = ValidationResult(
            False, True
        )
        detail = self.order._caa_check("o1")
        self.assertIn("CAA forbids issuance for www.example.com", detail)

    def test_004_missing_corroborator_fails_closed(self):
        self.order.caa_corroborator = None
        self.assertIsNotNone(self.order._caa_check("o1"))

    def test_005_no_identifiers_fails_closed(self):
        self.order.repository.order_lookup.return_value = {}
        self.assertIsNotNone(self.order._caa_check("o1"))

    def test_006_corroborator_exception_fails_closed(self):
        self.order.caa_corroborator.corroborate.side_effect = RuntimeError("boom")
        detail = self.order._caa_check("o1")
        self.assertIn("CAA check failed", detail)

    def test_007_non_dns_identifiers_skipped(self):
        self.order.repository.order_lookup.return_value = {
            "identifiers": json.dumps(
                [
                    {"type": "ip", "value": "192.0.2.1"},
                    {"type": "email", "value": "a@b"},
                ]
            )
        }
        self.assertIsNone(self.order._caa_check("o1"))
        self.order.caa_corroborator.corroborate.assert_not_called()

    def test_008_wildcard_flagged(self):
        self.order.repository.order_lookup.return_value = {
            "identifiers": json.dumps([{"type": "dns", "value": "*.example.com"}])
        }
        self.order._caa_check("o1")
        _, kwargs = self.order.caa_corroborator.corroborate.call_args
        self.assertTrue(kwargs["is_wildcard"])

    def test_009_all_dns_identifiers_checked(self):
        self.order.repository.order_lookup.return_value = {
            "identifiers": json.dumps(
                [
                    {"type": "dns", "value": "a.example.com"},
                    {"type": "dns", "value": "b.example.com"},
                ]
            )
        }
        self.assertIsNone(self.order._caa_check("o1"))
        self.assertEqual(self.order.caa_corroborator.corroborate.call_count, 2)

    def test_010_first_failure_stops(self):
        self.order.repository.order_lookup.return_value = {
            "identifiers": json.dumps(
                [
                    {"type": "dns", "value": "a.example.com"},
                    {"type": "dns", "value": "b.example.com"},
                ]
            )
        }
        self.order.caa_corroborator.corroborate.return_value = ValidationResult(
            False, True
        )
        detail = self.order._caa_check("o1")
        self.assertIn("a.example.com", detail)
        self.assertEqual(self.order.caa_corroborator.corroborate.call_count, 1)

    def test_011_account_uri_built(self):
        self.order._get_order_account_name = Mock(return_value="acct1")
        self.order._caa_check("o1")
        _, kwargs = self.order.caa_corroborator.corroborate.call_args
        self.assertEqual(kwargs["account_uri"], "http://acme.example/acme/acct/acct1")


class TestFinalizeBlocksOnCaa(unittest.TestCase):
    """_finalize_ready_order refuses issuance when CAA forbids it."""

    def setUp(self):
        self.order = _order()
        self.order.repository.order_update_if_status.return_value = 1
        self.order._authorizations_valid_for_issuance = Mock(return_value=True)
        self.order._finalize_csr = Mock(return_value=(200, None, None, "cert"))

    def test_020_caa_ok_proceeds_to_enrollment(self):
        self.order._caa_check = Mock(return_value=None)
        code, _, _, cert = self.order._finalize_ready_order("o1", {"csr": "x"})
        self.assertEqual(code, 200)
        self.assertEqual(cert, "cert")
        self.order._finalize_csr.assert_called_once()

    def test_021_caa_failure_blocks_enrollment(self):
        self.order._caa_check = Mock(return_value="CAA forbids issuance for x")
        code, message, detail, cert = self.order._finalize_ready_order(
            "o1", {"csr": "x"}
        )
        self.assertEqual(code, 403)
        self.assertEqual(message, "urn:ietf:params:acme:error:caa")
        self.assertIn("CAA forbids", detail)
        self.assertIsNone(cert)
        self.order._finalize_csr.assert_not_called()

    def test_022_caa_failure_marks_order_invalid(self):
        self.order._caa_check = Mock(return_value="nope")
        self.order._finalize_ready_order("o1", {"csr": "x"})
        self.order.repository.order_update.assert_called_with(
            {"name": "o1", "status": "invalid"}
        )


if __name__ == "__main__":
    unittest.main()
