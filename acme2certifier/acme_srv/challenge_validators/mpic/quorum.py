"""
Quorum policy for Multi-Perspective Issuance Corroboration (MPIC).

Encodes the CA/Browser Forum Baseline Requirements (BR) section 3.2.2.9 quorum
table and the phased enforcement rule.

Quorum table -- maximum tolerated non-corroborating remote perspectives:

    distinct remote perspectives used | allowed non-corroborations
    --------------------------------- | --------------------------
    2 - 5                             | 1
    6 or more                        | 2

A corroboration attempt passes when:

* the Primary Network Perspective itself confirms the challenge, AND
* the number of distinct remote perspectives used meets the configured minimum
  (>= 3 as of 2026-03-15; >= 5 as of 2026-12-15), AND
* the number of non-corroborating remote perspectives does not exceed the
  quorum table.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List
import logging

from .perspective import PerspectiveResult


class EnforcementMode(str, Enum):
    """How a failed quorum affects issuance."""

    MONITOR = "monitor"  # log the outcome but do not block on quorum failure
    ENFORCE = "enforce"  # block issuance when quorum is not met


def max_non_corroboration(remote_count: int) -> int:
    """Return the allowed number of non-corroborating remote perspectives.

    Per BR 3.2.2.9: 1 for 2-5 remote perspectives, 2 for 6 or more. Below 2
    remote perspectives the table does not apply and no non-corroboration is
    tolerated (such an attempt also fails the minimum-perspective check).
    """
    if remote_count >= 6:
        return 2
    if remote_count >= 2:
        return 1
    return 0


@dataclass
class QuorumDecision:
    """Structured outcome of a quorum evaluation (for logging/audit)."""

    compliant: bool
    primary_ok: bool
    remote_total: int
    remote_corroborating: int
    remote_non_corroborating: int
    allowed_non_corroborating: int
    min_remote_required: int
    reasons: List[str] = field(default_factory=list)


@dataclass
class QuorumPolicy:
    """Applies the BR quorum table and enforcement mode to perspective results."""

    min_remote_perspectives: int = 3
    enforcement: EnforcementMode = EnforcementMode.ENFORCE

    def evaluate(self, results: List[PerspectiveResult]) -> QuorumDecision:
        """Evaluate perspective results against the quorum rules."""
        primaries = [r for r in results if r.is_primary]
        remotes = [r for r in results if not r.is_primary]

        primary_ok = bool(primaries) and all(r.corroborates for r in primaries)
        remote_total = len(remotes)
        remote_corroborating = sum(1 for r in remotes if r.corroborates)
        remote_non_corroborating = remote_total - remote_corroborating
        allowed = max_non_corroboration(remote_total)

        reasons: List[str] = []
        if not primaries:
            reasons.append("no primary perspective result")
        elif not primary_ok:
            reasons.append("primary perspective did not corroborate")
        if remote_total < self.min_remote_perspectives:
            reasons.append(
                f"insufficient remote perspectives: {remote_total} < "
                f"{self.min_remote_perspectives}"
            )
        if remote_non_corroborating > allowed:
            reasons.append(
                f"too many non-corroborating remote perspectives: "
                f"{remote_non_corroborating} > {allowed}"
            )

        compliant = (
            primary_ok
            and remote_total >= self.min_remote_perspectives
            and remote_non_corroborating <= allowed
        )

        return QuorumDecision(
            compliant=compliant,
            primary_ok=primary_ok,
            remote_total=remote_total,
            remote_corroborating=remote_corroborating,
            remote_non_corroborating=remote_non_corroborating,
            allowed_non_corroborating=allowed,
            min_remote_required=self.min_remote_perspectives,
            reasons=reasons,
        )

    def is_issuance_allowed(
        self, decision: QuorumDecision, logger: logging.Logger = None
    ) -> bool:
        """Map a quorum decision to an issuance allow/deny under this mode.

        In ``MONITOR`` mode only the primary result gates issuance; the quorum
        outcome is reported but does not block (mirrors the 2025-03-15 ->
        2025-09-15 rollout phase). In ``ENFORCE`` mode full compliance is
        required.
        """
        if self.enforcement == EnforcementMode.MONITOR:
            if logger and not decision.compliant:
                logger.warning(
                    "MPIC monitor mode: quorum NOT met (%s) -- issuance not blocked",
                    "; ".join(decision.reasons) or "unknown",
                )
            return decision.primary_ok
        return decision.compliant
