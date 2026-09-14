"""
Challenge Validator Registry.

Provides a registry system for managing and accessing challenge validators.
"""

from typing import Dict, List, Optional, Set
import logging
from .base import (
    ChallengeValidator,
    ChallengeContext,
    ValidationResult,
    InvalidChallengeTypeError,
)
from .mpic import MpicCoordinator


class ChallengeValidatorRegistry:
    """Registry for managing challenge validators."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._validators: Dict[str, ChallengeValidator] = {}
        # Optional MPIC coordination -- unset means single-perspective (default)
        self._mpic_coordinator: Optional[MpicCoordinator] = None
        self._mpic_challenge_types: Set[str] = set()

    def enable_mpic(
        self, coordinator: MpicCoordinator, challenge_types: List[str]
    ) -> None:
        """Route the given challenge types through multi-perspective corroboration."""
        self.logger.debug("ChallengeValidatorRegistry.enable_mpic(%s)", challenge_types)
        self._mpic_coordinator = coordinator
        self._mpic_challenge_types = set(challenge_types)

    def register_validator(self, validator: ChallengeValidator) -> None:
        """Register a challenge validator."""
        self.logger.debug("ChallengeValidatorRegistry.register_validator()")
        challenge_type = validator.get_challenge_type()
        self._validators[challenge_type] = validator
        self.logger.debug(
            "ChallengeValidatorRegistry.register_validator(): Registered validator for challenge type: %s",
            challenge_type,
        )

    def get_validator(self, challenge_type: str) -> Optional[ChallengeValidator]:
        """Get a validator for the specified challenge type."""
        self.logger.debug(
            "ChallengeValidatorRegistry.get_validator(%s)", challenge_type
        )
        return self._validators.get(challenge_type)

    def get_supported_types(self) -> List[str]:
        """Get list of supported challenge types."""
        self.logger.debug("ChallengeValidatorRegistry.get_supported_types()")
        return list(self._validators.keys())

    def is_supported(self, challenge_type: str) -> bool:
        """Check if a challenge type is supported."""
        self.logger.debug("ChallengeValidatorRegistry.is_supported(%s)", challenge_type)
        return challenge_type in self._validators

    def validate_challenge(
        self, challenge_type: str, context: ChallengeContext
    ) -> ValidationResult:
        """Validate a challenge using the appropriate validator."""
        self.logger.debug(
            "ChallengeValidatorRegistry.validate_challenge(%s)", challenge_type
        )
        validator = self.get_validator(challenge_type)
        if not validator:
            raise InvalidChallengeTypeError(
                f"Unsupported challenge type: {challenge_type}"
            )

        if self._mpic_coordinator and challenge_type in self._mpic_challenge_types:
            self.logger.debug(
                "ChallengeValidatorRegistry.validate_challenge(): routing %s "
                "through MPIC coordinator",
                challenge_type,
            )
            return self._mpic_coordinator.corroborate(
                challenge_type, context, validator
            )

        return validator.validate_challenge(context)
