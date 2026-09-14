"""
Factory for building the active MPIC handler from configuration.

Both the DCV path (``challenge_registry_setup``) and the CAA corroborator use
this so the ``self_hosted`` / ``open_mpic`` selection, enforcement mode and
perspective/provider settings stay identical across check types.

A "handler" exposes ``corroborate(check_type, context, validator) -> ValidationResult``
-- satisfied by both :class:`MpicCoordinator` and :class:`ExternalMpicProvider`.
"""

from typing import Any, Union
import logging

from .coordinator import MpicCoordinator
from .external_provider import ExternalMpicProvider
from .quorum import EnforcementMode, QuorumPolicy
from .remote_agent import build_remote_perspectives

MpicHandler = Union[MpicCoordinator, ExternalMpicProvider]


def _enforcement(config: Any) -> EnforcementMode:
    try:
        return EnforcementMode(getattr(config, "mpic_enforcement", "enforce"))
    except ValueError:
        return EnforcementMode.ENFORCE


def build_self_hosted_coordinator(
    logger: logging.Logger, config: Any
) -> MpicCoordinator:
    """Build the built-in coordinator (method 3a)."""
    enforcement = _enforcement(config)
    policy = QuorumPolicy(
        min_remote_perspectives=getattr(config, "mpic_min_remote_perspectives", 3),
        enforcement=enforcement,
        min_distinct_regions=getattr(config, "mpic_min_distinct_regions", 1),
    )
    remote_perspectives = build_remote_perspectives(logger, config)
    logger.info(
        "MPIC handler: self_hosted (enforcement=%s, min_remote_perspectives=%d, "
        "remote_perspectives=%d)",
        enforcement.value,
        policy.min_remote_perspectives,
        len(remote_perspectives),
    )
    return MpicCoordinator(
        logger,
        policy=policy,
        remote_perspectives=remote_perspectives,
        perspective_timeout=getattr(config, "mpic_perspective_timeout", 10),
    )


def build_external_provider(
    logger: logging.Logger, config: Any
) -> ExternalMpicProvider:
    """Build the external Open MPIC provider adapter (method 3b)."""
    enforcement = _enforcement(config)
    logger.info(
        "MPIC handler: open_mpic (enforcement=%s, url=%s)",
        enforcement.value,
        getattr(config, "mpic_provider_url", None),
    )
    return ExternalMpicProvider(
        logger,
        url=getattr(config, "mpic_provider_url", None),
        api_key=getattr(config, "mpic_provider_api_key", None),
        token=getattr(config, "mpic_provider_token", None),
        enforcement=enforcement,
        timeout=getattr(config, "mpic_perspective_timeout", 10),
        client_cert=getattr(config, "mpic_client_cert", None),
        client_key=getattr(config, "mpic_client_key", None),
        ca_bundle=getattr(config, "mpic_ca_bundle", None),
        perspective_count=getattr(config, "mpic_provider_perspective_count", None),
        quorum_count=getattr(config, "mpic_provider_quorum_count", None),
    )


def build_mpic_handler(logger: logging.Logger, config: Any) -> MpicHandler:
    """Build the handler selected by ``config.mpic_provider``."""
    if getattr(config, "mpic_provider", "self_hosted") == "open_mpic":
        return build_external_provider(logger, config)
    return build_self_hosted_coordinator(logger, config)
