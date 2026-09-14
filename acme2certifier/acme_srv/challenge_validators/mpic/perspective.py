"""
Network perspectives for Multi-Perspective Issuance Corroboration (MPIC).

A *perspective* is a place that can run a challenge validator against a
:class:`ChallengeContext` and return a structured result. The unit of work a
perspective performs is exactly a validator's ``perform_validation`` -- so the
Primary Network Perspective (this process) and any remote perspective share the
same contract.

This module ships the abstraction plus the :class:`LocalPerspective`
(the Primary). Remote implementations (self-hosted agents, external providers)
are added in later changes and only need to implement :meth:`validate`.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional
import logging
import time

from ..base import ChallengeContext, ChallengeValidator, ValidationResult


@dataclass
class PerspectiveMetadata:
    """Declared location/topology metadata for a network perspective.

    The software cannot verify physical distance or true network diversity;
    this metadata is operator-declared and used for policy checks and the
    audit trail (see ``docs/mpic.md`` section 8).
    """

    name: str
    region: Optional[str] = None
    country: Optional[str] = None  # ISO code of State/Province/Country
    asn: Optional[str] = None
    url: Optional[str] = None


@dataclass
class PerspectiveResult:
    """Outcome of validation performed from a single perspective."""

    perspective_name: str
    is_primary: bool
    success: bool
    invalid: bool
    error_message: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    metadata: Optional[PerspectiveMetadata] = None
    elapsed_ms: Optional[float] = None

    @property
    def corroborates(self) -> bool:
        """True when this perspective positively confirms the challenge."""
        return bool(self.success) and not self.invalid


class RemotePerspective(ABC):
    """Abstract base class for a network perspective."""

    def __init__(
        self,
        logger: logging.Logger,
        metadata: PerspectiveMetadata,
        is_primary: bool = False,
    ):
        self.logger = logger
        self.metadata = metadata
        self.is_primary = is_primary

    @property
    def name(self) -> str:
        """Return the perspective name."""
        return self.metadata.name

    @abstractmethod
    def validate(
        self, challenge_type: str, context: ChallengeContext
    ) -> PerspectiveResult:
        """Run validation for ``challenge_type`` from this perspective."""
        raise NotImplementedError  # pragma: no cover

    def _timed(self, func) -> PerspectiveResult:
        """Run ``func`` (returning a PerspectiveResult), recording elapsed time.

        Any exception is turned into a non-corroborating result so that one
        misbehaving perspective never aborts the whole corroboration attempt.
        """
        start = time.monotonic()
        try:
            result = func()
        except Exception as err:  # noqa: BLE001 - isolate a single perspective
            self.logger.error(
                "MPIC perspective %s raised during validation: %s", self.name, err
            )
            result = PerspectiveResult(
                perspective_name=self.name,
                is_primary=self.is_primary,
                success=False,
                invalid=True,
                error_message=str(err),
                metadata=self.metadata,
            )
        result.elapsed_ms = (time.monotonic() - start) * 1000.0
        return result


class LocalPerspective(RemotePerspective):
    """The Primary Network Perspective -- runs the validator in-process."""

    def __init__(
        self,
        logger: logging.Logger,
        validator: ChallengeValidator,
        metadata: Optional[PerspectiveMetadata] = None,
    ):
        super().__init__(
            logger,
            metadata or PerspectiveMetadata(name="primary"),
            is_primary=True,
        )
        self.validator = validator

    def validate(
        self, challenge_type: str, context: ChallengeContext
    ) -> PerspectiveResult:
        self.logger.debug("LocalPerspective.validate(%s)", challenge_type)

        def _run() -> PerspectiveResult:
            result: ValidationResult = self.validator.validate_challenge(context)
            return PerspectiveResult(
                perspective_name=self.name,
                is_primary=True,
                success=result.success,
                invalid=result.invalid,
                error_message=result.error_message,
                evidence=result.details,
                metadata=self.metadata,
            )

        return self._timed(_run)
