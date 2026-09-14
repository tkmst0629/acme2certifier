#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Unit tests for the MPIC coordination layer (challenge_validators/mpic)."""

# pylint: disable=C0415, R0904, W0212
import sys
import logging
import unittest
from unittest.mock import Mock

sys.path.insert(0, ".")
sys.path.insert(1, "..")

from acme2certifier.acme_srv.challenge_validators.base import (
    ChallengeValidator,
    ChallengeContext,
    ValidationResult,
)
from acme2certifier.acme_srv.challenge_validators.mpic import (
    MpicCoordinator,
    QuorumPolicy,
    EnforcementMode,
    LocalPerspective,
    RemotePerspective,
    PerspectiveResult,
    PerspectiveMetadata,
)
from acme2certifier.acme_srv.challenge_validators.mpic.quorum import (
    max_non_corroboration,
)
from acme2certifier.acme_srv.challenge_validators.registry import (
    ChallengeValidatorRegistry,
)


class _FakeValidator(ChallengeValidator):
    """A minimal validator returning a preset result."""

    def __init__(self, logger, ok=True, ctype="dns-01"):
        super().__init__(logger)
        self._ok = ok
        self._ctype = ctype

    def get_challenge_type(self):
        return self._ctype

    def perform_validation(self, context):
        return ValidationResult(
            success=self._ok, invalid=not self._ok, details={"probe": 1}
        )


class _FakeRemote(RemotePerspective):
    """A remote perspective returning a preset result."""

    def __init__(self, logger, name, ok):
        super().__init__(
            logger, PerspectiveMetadata(name=name, country="US"), is_primary=False
        )
        self._ok = ok

    def validate(self, challenge_type, context):
        return self._timed(
            lambda: PerspectiveResult(
                self.name,
                is_primary=False,
                success=self._ok,
                invalid=not self._ok,
                metadata=self.metadata,
            )
        )


def _pr(name, primary, ok):
    return PerspectiveResult(name, primary, success=ok, invalid=not ok)


def _ctx():
    return ChallengeContext(
        challenge_name="c1",
        token="tok",
        jwk_thumbprint="jwk",
        authorization_type="dns",
        authorization_value="example.com",
    )


class TestQuorumTable(unittest.TestCase):
    """BR 3.2.2.9 quorum table."""

    def test_001_below_two(self):
        self.assertEqual(max_non_corroboration(0), 0)
        self.assertEqual(max_non_corroboration(1), 0)

    def test_002_two_to_five(self):
        for n in (2, 3, 4, 5):
            self.assertEqual(max_non_corroboration(n), 1)

    def test_003_six_or_more(self):
        for n in (6, 7, 20):
            self.assertEqual(max_non_corroboration(n), 2)


class TestQuorumPolicy(unittest.TestCase):
    """QuorumPolicy.evaluate / is_issuance_allowed."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_010_all_good_compliant(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE)
        d = pol.evaluate(
            [
                _pr("p", True, True),
                _pr("a", False, True),
                _pr("b", False, True),
                _pr("c", False, True),
            ]
        )
        self.assertTrue(d.compliant)
        self.assertTrue(pol.is_issuance_allowed(d))

    def test_011_one_non_corroborating_allowed(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE)
        d = pol.evaluate(
            [
                _pr("p", True, True),
                _pr("a", False, True),
                _pr("b", False, True),
                _pr("c", False, False),
            ]
        )
        self.assertTrue(d.compliant)
        self.assertEqual(d.remote_non_corroborating, 1)

    def test_012_two_non_corroborating_denied(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE)
        d = pol.evaluate(
            [
                _pr("p", True, True),
                _pr("a", False, True),
                _pr("b", False, False),
                _pr("c", False, False),
            ]
        )
        self.assertFalse(d.compliant)
        self.assertIn("too many non-corroborating", "; ".join(d.reasons))

    def test_013_primary_failure_denied(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE)
        d = pol.evaluate(
            [
                _pr("p", True, False),
                _pr("a", False, True),
                _pr("b", False, True),
                _pr("c", False, True),
            ]
        )
        self.assertFalse(d.compliant)
        self.assertFalse(d.primary_ok)

    def test_014_missing_primary_denied(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE)
        d = pol.evaluate(
            [_pr("a", False, True), _pr("b", False, True), _pr("c", False, True)]
        )
        self.assertFalse(d.compliant)
        self.assertIn("no primary perspective result", d.reasons)

    def test_015_too_few_remotes_denied(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE)
        d = pol.evaluate([_pr("p", True, True), _pr("a", False, True)])
        self.assertFalse(d.compliant)
        self.assertIn("insufficient remote perspectives", "; ".join(d.reasons))

    def test_016_monitor_mode_does_not_block_on_quorum(self):
        pol = QuorumPolicy(3, EnforcementMode.MONITOR)
        d = pol.evaluate([_pr("p", True, True)])
        self.assertFalse(d.compliant)
        self.assertTrue(pol.is_issuance_allowed(d, self.logger))

    def test_017_monitor_mode_still_requires_primary(self):
        pol = QuorumPolicy(3, EnforcementMode.MONITOR)
        d = pol.evaluate([_pr("p", True, False)])
        self.assertFalse(pol.is_issuance_allowed(d, self.logger))


class TestPerspectives(unittest.TestCase):
    """LocalPerspective and error isolation."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_020_local_perspective_maps_result(self):
        lp = LocalPerspective(self.logger, _FakeValidator(self.logger, ok=True))
        res = lp.validate("dns-01", _ctx())
        self.assertTrue(res.is_primary)
        self.assertTrue(res.corroborates)
        self.assertEqual(res.evidence, {"probe": 1})
        self.assertIsNotNone(res.elapsed_ms)

    def test_021_local_perspective_failure(self):
        lp = LocalPerspective(self.logger, _FakeValidator(self.logger, ok=False))
        res = lp.validate("dns-01", _ctx())
        self.assertFalse(res.corroborates)
        self.assertTrue(res.invalid)

    def test_022_exception_isolated_as_non_corroboration(self):
        class _Boom(RemotePerspective):
            def __init__(self, logger):
                super().__init__(logger, PerspectiveMetadata(name="boom"))

            def validate(self, challenge_type, context):
                return self._timed(self._raise)

            def _raise(self):
                raise RuntimeError("network down")

        res = _Boom(self.logger).validate("dns-01", _ctx())
        self.assertFalse(res.corroborates)
        self.assertIn("network down", res.error_message)


class TestCoordinator(unittest.TestCase):
    """MpicCoordinator.corroborate end to end."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_030_enforce_all_good_valid(self):
        coord = MpicCoordinator(
            self.logger,
            QuorumPolicy(3, EnforcementMode.ENFORCE),
            remote_perspectives=[
                _FakeRemote(self.logger, "a", True),
                _FakeRemote(self.logger, "b", True),
                _FakeRemote(self.logger, "c", True),
            ],
        )
        r = coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        self.assertTrue(r.success)
        self.assertFalse(r.invalid)
        self.assertTrue(r.details["mpic"]["compliant"])
        self.assertEqual(len(r.details["perspectives"]), 4)

    def test_031_enforce_no_remotes_invalid(self):
        coord = MpicCoordinator(
            self.logger,
            QuorumPolicy(3, EnforcementMode.ENFORCE),
            remote_perspectives=[],
        )
        r = coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        self.assertFalse(r.success)
        self.assertTrue(r.invalid)
        self.assertIn("incorrectResponse", r.error_message)

    def test_032_enforce_two_failures_invalid(self):
        coord = MpicCoordinator(
            self.logger,
            QuorumPolicy(3, EnforcementMode.ENFORCE),
            remote_perspectives=[
                _FakeRemote(self.logger, "a", True),
                _FakeRemote(self.logger, "b", False),
                _FakeRemote(self.logger, "c", False),
            ],
        )
        r = coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        self.assertFalse(r.success)

    def test_033_monitor_no_remotes_but_primary_ok_valid(self):
        coord = MpicCoordinator(
            self.logger,
            QuorumPolicy(3, EnforcementMode.MONITOR),
            remote_perspectives=[],
        )
        r = coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        self.assertTrue(r.success)
        self.assertFalse(r.details["mpic"]["compliant"])

    def test_034_monitor_primary_failure_invalid(self):
        coord = MpicCoordinator(
            self.logger,
            QuorumPolicy(3, EnforcementMode.MONITOR),
            remote_perspectives=[],
        )
        r = coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, False))
        self.assertFalse(r.success)

    def test_035_timeout_counts_as_non_corroboration(self):
        import time

        class _Slow(RemotePerspective):
            def __init__(self, logger):
                super().__init__(logger, PerspectiveMetadata(name="slow"))

            def validate(self, challenge_type, context):
                time.sleep(2)
                return self._timed(
                    lambda: PerspectiveResult(self.name, False, True, False)
                )

        coord = MpicCoordinator(
            self.logger,
            QuorumPolicy(1, EnforcementMode.ENFORCE),
            remote_perspectives=[_Slow(self.logger)],
            perspective_timeout=1,
        )
        r = coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        self.assertFalse(r.success)
        slow = [p for p in r.details["perspectives"] if p["name"] == "slow"][0]
        self.assertFalse(slow["corroborates"])


class TestRegistryRouting(unittest.TestCase):
    """ChallengeValidatorRegistry MPIC routing."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_040_default_is_single_perspective(self):
        reg = ChallengeValidatorRegistry(self.logger)
        reg.register_validator(_FakeValidator(self.logger, True))
        r = reg.validate_challenge("dns-01", _ctx())
        self.assertTrue(r.success)
        self.assertNotIn("mpic", r.details or {})

    def test_041_enabled_routes_eligible_type(self):
        reg = ChallengeValidatorRegistry(self.logger)
        reg.register_validator(_FakeValidator(self.logger, True))
        reg.enable_mpic(
            MpicCoordinator(
                self.logger,
                QuorumPolicy(3, EnforcementMode.ENFORCE),
                remote_perspectives=[],
            ),
            ["dns-01"],
        )
        r = reg.validate_challenge("dns-01", _ctx())
        self.assertIn("mpic", r.details)
        self.assertFalse(r.success)

    def test_042_enabled_does_not_route_ineligible_type(self):
        reg = ChallengeValidatorRegistry(self.logger)
        reg.register_validator(_FakeValidator(self.logger, True, ctype="dns-01"))
        # enable MPIC only for http-01; dns-01 must stay single-perspective
        reg.enable_mpic(
            MpicCoordinator(
                self.logger,
                QuorumPolicy(3, EnforcementMode.ENFORCE),
                remote_perspectives=[],
            ),
            ["http-01"],
        )
        r = reg.validate_challenge("dns-01", _ctx())
        self.assertTrue(r.success)
        self.assertNotIn("mpic", r.details or {})


class _SetupConfig:
    """Lightweight config object for create_challenge_validator_registry."""

    def __init__(self, **kwargs):
        self.dns_persist_01_support = kwargs.get("dns_persist_01_support", False)
        self.email_identifier_support = kwargs.get("email_identifier_support", False)
        self.tnauthlist_support = kwargs.get("tnauthlist_support", False)
        self.forward_address_check = kwargs.get("forward_address_check", False)
        self.reverse_address_check = kwargs.get("reverse_address_check", False)
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestRegistrySetup(unittest.TestCase):
    """create_challenge_validator_registry MPIC enablement."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_050_disabled_by_default(self):
        from acme2certifier.acme_srv.challenge_registry_setup import (
            create_challenge_validator_registry,
        )

        reg = create_challenge_validator_registry(self.logger, _SetupConfig())
        self.assertIsNone(reg._mpic_coordinator)

    def test_051_enabled_wires_coordinator(self):
        from acme2certifier.acme_srv.challenge_registry_setup import (
            create_challenge_validator_registry,
        )

        reg = create_challenge_validator_registry(
            self.logger,
            _SetupConfig(
                mpic_enabled=True,
                mpic_enforcement="monitor",
                mpic_min_remote_perspectives=5,
                mpic_perspective_timeout=7,
            ),
        )
        self.assertIsNotNone(reg._mpic_coordinator)
        self.assertEqual(
            reg._mpic_challenge_types, {"http-01", "dns-01", "tls-alpn-01"}
        )
        self.assertEqual(
            reg._mpic_coordinator.policy.enforcement, EnforcementMode.MONITOR
        )
        self.assertEqual(reg._mpic_coordinator.policy.min_remote_perspectives, 5)
        self.assertEqual(reg._mpic_coordinator.perspective_timeout, 7)

    def test_052_invalid_enforcement_falls_back_to_enforce(self):
        from acme2certifier.acme_srv.challenge_registry_setup import (
            create_challenge_validator_registry,
        )

        reg = create_challenge_validator_registry(
            self.logger, _SetupConfig(mpic_enabled=True, mpic_enforcement="bogus")
        )
        self.assertEqual(
            reg._mpic_coordinator.policy.enforcement, EnforcementMode.ENFORCE
        )


if __name__ == "__main__":
    unittest.main()
