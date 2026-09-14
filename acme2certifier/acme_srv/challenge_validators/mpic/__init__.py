"""
Multi-Perspective Issuance Corroboration (MPIC) coordination layer.

Implements the coordination core that lets challenge validation be corroborated
from multiple, geographically/topologically distinct network perspectives, as
required by CA/Browser Forum Baseline Requirements section 3.2.2.9.

See ``docs/mpic.md`` for the design.

This package provides:

* ``RemotePerspective`` / ``LocalPerspective`` -- a "place" that can run a
  validator against a :class:`ChallengeContext` and return a result.
* ``QuorumPolicy`` -- encodes the BR quorum table and enforcement phase.
* ``MpicCoordinator`` -- fans out to perspectives and applies the quorum.

With MPIC disabled (the default) none of this is instantiated and the existing
single-perspective validation path runs unchanged.
"""

from .perspective import (
    PerspectiveMetadata,
    PerspectiveResult,
    RemotePerspective,
    LocalPerspective,
)
from .quorum import QuorumPolicy, EnforcementMode, QuorumDecision
from .coordinator import MpicCoordinator

__all__ = [
    "PerspectiveMetadata",
    "PerspectiveResult",
    "RemotePerspective",
    "LocalPerspective",
    "QuorumPolicy",
    "EnforcementMode",
    "QuorumDecision",
    "MpicCoordinator",
]
