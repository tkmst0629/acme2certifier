# pylint: disable=R0913, R0917
"""
Multi-perspective CAA corroboration entry point.

``CaaCorroborator`` runs a CAA policy check across the configured MPIC handler
(the built-in coordinator with its remote agents, or an external Open MPIC
service) and returns a single :class:`ValidationResult` whose ``success`` means
"issuance is permitted by CAA, corroborated across perspectives".

This is a standalone component + API; wiring it into the issuance/finalize flow
is intentionally left to the caller.

Usage::

    corroborator = build_caa_corroborator(logger, config)
    result = corroborator.corroborate(
        "www.example.com",
        issuer_identities=["ca.example"],
        account_uri="https://acme.example/acct/1",
        is_wildcard=False,
    )
    if not result.success:
        # refuse issuance
        ...
"""

from typing import Any, List, Optional
import logging

from ..base import ChallengeContext, ValidationResult
from .caa_checker import CaaChecker
from .factory import MpicHandler, build_mpic_handler

CAA_CHECK_TYPE = "caa"


class CaaCorroborator:
    """Corroborates a CAA policy decision across MPIC perspectives."""

    def __init__(
        self,
        logger: logging.Logger,
        handler: MpicHandler,
        checker: Optional[CaaChecker] = None,
    ):
        self.logger = logger
        self.handler = handler
        self.checker = checker or CaaChecker(logger)

    def corroborate(
        self,
        identifier: str,
        issuer_identities: List[str],
        account_uri: Optional[str] = None,
        is_wildcard: bool = False,
        validation_method: Optional[str] = None,
        dns_servers: Optional[List[str]] = None,
    ) -> ValidationResult:
        """Run a multi-perspective CAA check for ``identifier``."""
        self.logger.debug("CaaCorroborator.corroborate(%s)", identifier)

        value = identifier
        if is_wildcard and not value.startswith("*."):
            value = f"*.{value}"

        context = ChallengeContext(
            challenge_name=f"caa:{identifier}",
            token="",
            jwk_thumbprint="",
            authorization_type="dns",
            authorization_value=value,
            dns_servers=dns_servers,
            options={
                "issuer_domain_names": issuer_identities or [],
                "accounturi": account_uri,
                "validation_method": validation_method,
            },
        )
        return self.handler.corroborate(CAA_CHECK_TYPE, context, self.checker)


def build_caa_corroborator(logger: logging.Logger, config: Any) -> CaaCorroborator:
    """Build a :class:`CaaCorroborator` using the configured MPIC handler.

    Reuses ``mpic_provider`` and the perspective/provider settings, so CAA is
    corroborated exactly like DCV (same agents / same external service).
    """
    logger.debug("mpic.build_caa_corroborator()")
    handler = build_mpic_handler(logger, config)
    return CaaCorroborator(logger, handler, CaaChecker(logger))
