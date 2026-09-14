#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Unit tests for MPIC diversity guard, audit logging and metrics (PR4)."""

# pylint: disable=C0415, R0904, W0212
import sys
import json
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
    MpicStats,
    QuorumPolicy,
    EnforcementMode,
    RemotePerspective,
    PerspectiveResult,
    PerspectiveMetadata,
)


class _FakeValidator(ChallengeValidator):
    def __init__(self, logger, ok=True, ctype="dns-01"):
        super().__init__(logger)
        self._ok = ok
        self._ctype = ctype

    def get_challenge_type(self):
        return self._ctype

    def perform_validation(self, context):
        return ValidationResult(success=self._ok, invalid=not self._ok, details={})


class _FakeRemote(RemotePerspective):
    def __init__(self, logger, name, ok, country=None):
        super().__init__(
            logger, PerspectiveMetadata(name=name, country=country), is_primary=False
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


def _pr(name, primary, ok, country=None):
    return PerspectiveResult(
        name,
        primary,
        success=ok,
        invalid=not ok,
        metadata=PerspectiveMetadata(name=name, country=country),
    )


def _ctx():
    return ChallengeContext(
        challenge_name="c1",
        token="t",
        jwk_thumbprint="j",
        authorization_type="dns",
        authorization_value="example.com",
    )


class TestDiversityGuard(unittest.TestCase):
    """QuorumPolicy.min_distinct_regions."""

    def test_001_same_country_fails_diversity(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE, min_distinct_regions=2)
        d = pol.evaluate(
            [
                _pr("p", True, True, "US"),
                _pr("a", False, True, "US"),
                _pr("b", False, True, "US"),
                _pr("c", False, True, "US"),
            ]
        )
        self.assertEqual(d.distinct_regions, 1)
        self.assertFalse(d.compliant)
        self.assertIn("insufficient network diversity", "; ".join(d.reasons))

    def test_002_distinct_countries_pass(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE, min_distinct_regions=2)
        d = pol.evaluate(
            [
                _pr("p", True, True, "US"),
                _pr("a", False, True, "US"),
                _pr("b", False, True, "DE"),
                _pr("c", False, True, "JP"),
            ]
        )
        self.assertEqual(d.distinct_regions, 3)
        self.assertTrue(d.compliant)

    def test_003_default_off_does_not_require_diversity(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE)  # min_distinct_regions=1
        d = pol.evaluate(
            [
                _pr("p", True, True, "US"),
                _pr("a", False, True, "US"),
                _pr("b", False, True, "US"),
                _pr("c", False, True, "US"),
            ]
        )
        self.assertTrue(d.compliant)

    def test_004_only_corroborating_count_towards_diversity(self):
        pol = QuorumPolicy(3, EnforcementMode.ENFORCE, min_distinct_regions=2)
        # a failing perspective in a second country must not satisfy diversity
        d = pol.evaluate(
            [
                _pr("p", True, True, "US"),
                _pr("a", False, True, "US"),
                _pr("b", False, True, "US"),
                _pr("c", False, False, "DE"),
            ]
        )
        self.assertEqual(d.distinct_regions, 1)
        self.assertFalse(d.compliant)


class TestAuditAndStats(unittest.TestCase):
    """Structured audit record + in-process metrics."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _coord(self, remotes, enforcement=EnforcementMode.ENFORCE, regions=1):
        return MpicCoordinator(
            self.logger,
            QuorumPolicy(3, enforcement, min_distinct_regions=regions),
            remote_perspectives=remotes,
        )

    def test_010_audit_record_emitted_as_json(self):
        coord = self._coord(
            [
                _FakeRemote(self.logger, "a", True, "US"),
                _FakeRemote(self.logger, "b", True, "DE"),
                _FakeRemote(self.logger, "c", True, "JP"),
            ]
        )
        coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        audit_calls = [
            c
            for c in self.logger.info.call_args_list
            if c.args and c.args[0] == "MPIC-AUDIT %s"
        ]
        self.assertEqual(len(audit_calls), 1)
        record = json.loads(audit_calls[0].args[1])
        self.assertEqual(record["event"], "mpic_corroboration")
        self.assertEqual(record["decision"], "allow")
        self.assertEqual(record["challenge_type"], "dns-01")
        self.assertEqual(len(record["perspectives"]), 4)
        self.assertEqual(record["quorum"]["distinct_regions"], 3)

    def test_011_stats_accumulate(self):
        coord = self._coord(
            [
                _FakeRemote(self.logger, "a", True, "US"),
                _FakeRemote(self.logger, "b", True, "DE"),
                _FakeRemote(self.logger, "c", False, "JP"),
            ]
        )
        # 3 remotes, 1 failing -> still allowed under quorum
        coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        # primary fails -> denied
        coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, False))

        self.assertIsInstance(coord.stats, MpicStats)
        self.assertEqual(coord.stats.attempts, 2)
        self.assertEqual(coord.stats.allowed, 1)
        self.assertEqual(coord.stats.denied, 1)
        self.assertEqual(coord.stats.primary_failures, 1)
        self.assertEqual(coord.stats.perspective_non_corroborations.get("c"), 2)
        snap = coord.stats.as_dict()
        self.assertEqual(snap["attempts"], 2)

    def test_012_diversity_failure_denies_in_enforce(self):
        coord = self._coord(
            [
                _FakeRemote(self.logger, "a", True, "US"),
                _FakeRemote(self.logger, "b", True, "US"),
                _FakeRemote(self.logger, "c", True, "US"),
            ],
            regions=2,
        )
        r = coord.corroborate("dns-01", _ctx(), _FakeValidator(self.logger, True))
        self.assertFalse(r.success)
        self.assertEqual(r.details["mpic"]["distinct_regions"], 1)


class TestMultiChallengeTypeCoverage(unittest.TestCase):
    """Coordinator is challenge-type agnostic: http-01 / tls-alpn-01 too."""

    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _coord(self):
        return MpicCoordinator(
            self.logger,
            QuorumPolicy(2, EnforcementMode.ENFORCE),
            remote_perspectives=[
                _FakeRemote(self.logger, "a", True, "US"),
                _FakeRemote(self.logger, "b", True, "DE"),
            ],
        )

    def test_020_http01(self):
        r = self._coord().corroborate(
            "http-01", _ctx(), _FakeValidator(self.logger, True, ctype="http-01")
        )
        self.assertTrue(r.success)

    def test_021_tls_alpn01(self):
        r = self._coord().corroborate(
            "tls-alpn-01",
            _ctx(),
            _FakeValidator(self.logger, True, ctype="tls-alpn-01"),
        )
        self.assertTrue(r.success)


if __name__ == "__main__":
    unittest.main()
