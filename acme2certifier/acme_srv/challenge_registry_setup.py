"""
Registry setup utilities for creating and configuring challenge validator registries.

This module provides factory functions for creating pre-configured challenge
validator registries with all standard ACME challenge types.
"""

from typing import Dict, Any, Optional
import logging
from .challenge_validators import (
    ChallengeValidatorRegistry,
    HttpChallengeValidator,
    DnsChallengeValidator,
    DnsPersistChallengeValidator,
    TlsAlpnChallengeValidator,
    EmailReplyChallengeValidator,
    TkauthChallengeValidator,
    SourceAddressValidator,
    MpicCoordinator,
    QuorumPolicy,
    EnforcementMode,
    build_remote_perspectives,
    MPIC_CHALLENGE_TYPES,
)


def create_challenge_validator_registry(
    logger: logging.Logger, config: Optional[Dict[str, Any]] = None
) -> ChallengeValidatorRegistry:
    """Create a fully configured challenge validator registry with all standard validators"""

    logger.debug("challenge_registry_setup.create_challenge_validator_registry()")
    registry = ChallengeValidatorRegistry(logger)

    # Register standard ACME challenge validators
    registry.register_validator(HttpChallengeValidator(logger))
    registry.register_validator(DnsChallengeValidator(logger))

    if config.dns_persist_01_support:
        registry.register_validator(DnsPersistChallengeValidator(logger))
    registry.register_validator(TlsAlpnChallengeValidator(logger))
    if config.email_identifier_support:
        # Register Email-Reply challenge validator if configured
        registry.register_validator(EmailReplyChallengeValidator(logger))
    if config.tnauthlist_support:
        # Register Tkauth challenge validator if configured
        registry.register_validator(TkauthChallengeValidator(logger))

    # Register Source Address validator if address checking is enabled
    # if config.forward_address_check or config.reverse_address_check:
    registry.register_validator(
        SourceAddressValidator(
            logger,
            forward_check=config.forward_address_check,
            reverse_check=config.reverse_address_check,
        )
    )

    # Enable Multi-Perspective Issuance Corroboration if configured
    if getattr(config, "mpic_enabled", False):
        _enable_mpic(logger, registry, config)

    logger.debug(
        "create_challenge_validator_registry(): Registry created with %d validators: %s",
        len(registry.get_supported_types()),
        ", ".join(registry.get_supported_types()),
    )

    logger.debug("challenge_registry_setup.create_challenge_validator_registry() ended")
    return registry


def _enable_mpic(
    logger: logging.Logger,
    registry: ChallengeValidatorRegistry,
    config: Any,
) -> None:
    """Attach an MPIC coordinator to the registry based on configuration.

    Remote perspectives are built from ``config.mpic_perspectives``. With none
    configured the coordinator runs the Primary perspective only, which fails
    the quorum in 'enforce' mode (as it must -- MPIC requires remote
    perspectives) and logs without blocking in 'monitor' mode.
    """
    logger.debug("challenge_registry_setup._enable_mpic()")
    try:
        enforcement = EnforcementMode(getattr(config, "mpic_enforcement", "enforce"))
    except ValueError:
        enforcement = EnforcementMode.ENFORCE

    policy = QuorumPolicy(
        min_remote_perspectives=getattr(config, "mpic_min_remote_perspectives", 3),
        enforcement=enforcement,
        min_distinct_regions=getattr(config, "mpic_min_distinct_regions", 1),
    )
    remote_perspectives = build_remote_perspectives(logger, config)
    coordinator = MpicCoordinator(
        logger,
        policy=policy,
        remote_perspectives=remote_perspectives,
        perspective_timeout=getattr(config, "mpic_perspective_timeout", 10),
    )
    registry.enable_mpic(coordinator, MPIC_CHALLENGE_TYPES)
    logger.info(
        "MPIC enabled (enforcement=%s, min_remote_perspectives=%d, "
        "remote_perspectives=%d) for: %s",
        enforcement.value,
        policy.min_remote_perspectives,
        len(remote_perspectives),
        ", ".join(MPIC_CHALLENGE_TYPES),
    )


def create_custom_registry(
    logger: logging.Logger,
    validator_classes: list,
    _config: Optional[Dict[str, Any]] = None,
) -> ChallengeValidatorRegistry:
    """
    Create a custom challenge validator registry with specified validators.

    Args:
        logger: Logger instance for validation operations
        validator_classes: List of validator classes to register
        config: Optional configuration dictionary for validator setup

    Returns:
        ChallengeValidatorRegistry: Configured registry with specified validators
    """
    registry = ChallengeValidatorRegistry(logger)

    for validator_class in validator_classes:
        validator = validator_class(logger)
        registry.register_validator(validator)

    logger.info(
        "Custom challenge validator registry created with %d validators",
        len(registry.get_supported_types()),
    )

    return registry
