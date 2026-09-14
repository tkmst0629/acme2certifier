"""
MPIC remote agent (method 3a, server side).

An agent runs the standard challenge validators from its own network location
and answers corroboration requests coming from a coordinator (see
:class:`RemoteAgentPerspective`). This module holds the framework-agnostic
logic; the HTTP/auth wrapper lives in :mod:`.agent_wsgi`.

The agent validates from *its own* vantage point: unless told otherwise it
ignores any resolver / proxy pinned in the forwarded context and uses its local
resolver, so each perspective genuinely queries from a different place (which is
the whole point of MPIC).
"""

from typing import TYPE_CHECKING, Any, Dict, List, Optional
import logging

from ..base import ChallengeValidator, ValidationResult
from ..http_validator import HttpChallengeValidator
from ..dns_validator import DnsChallengeValidator
from ..tls_alpn_validator import TlsAlpnChallengeValidator
from .protocol import (
    MPIC_CHALLENGE_TYPES,
    payload_to_context,
    validation_result_to_payload,
)

if TYPE_CHECKING:  # avoid a runtime import cycle (registry imports this package)
    from ..registry import ChallengeValidatorRegistry


class MpicAgent:
    """Runs a validator locally on behalf of a coordinator and returns the result."""

    def __init__(
        self,
        logger: logging.Logger,
        registry: "ChallengeValidatorRegistry",
        eligible_types: Optional[List[str]] = None,
        use_local_resolver: bool = True,
    ):
        self.logger = logger
        self.registry = registry
        self.eligible_types = list(eligible_types or MPIC_CHALLENGE_TYPES)
        self.use_local_resolver = use_local_resolver

    def validate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a corroboration request payload and return a result payload."""
        challenge_type = (payload or {}).get("challenge_type")
        self.logger.debug("MpicAgent.validate(%s)", challenge_type)

        if challenge_type not in self.eligible_types:
            self.logger.warning(
                "MpicAgent.validate(): unsupported challenge_type %r", challenge_type
            )
            return validation_result_to_payload(
                ValidationResult(
                    success=False,
                    invalid=True,
                    error_message=f"unsupported challenge_type: {challenge_type}",
                    details={"eligible_types": self.eligible_types},
                )
            )

        context = payload_to_context((payload or {}).get("context") or {})
        if self.use_local_resolver:
            # validate from this agent's own vantage point
            context.dns_servers = None
            context.proxy_servers = None

        result = self.registry.validate_challenge(challenge_type, context)
        return validation_result_to_payload(result)


def build_agent(
    logger: logging.Logger,
    eligible_types: Optional[List[str]] = None,
    use_local_resolver: bool = True,
) -> MpicAgent:
    """Build an :class:`MpicAgent` with the standard DCV validators registered.

    The registry is built without MPIC enabled, so the agent performs plain
    single-perspective validation and never fans out to further perspectives.
    """
    logger.debug("mpic.build_agent()")
    # imported here to avoid an import cycle at package load time
    # pylint: disable=import-outside-toplevel
    from ..registry import ChallengeValidatorRegistry

    registry = ChallengeValidatorRegistry(logger)
    validators: List[ChallengeValidator] = [
        HttpChallengeValidator(logger),
        DnsChallengeValidator(logger),
        TlsAlpnChallengeValidator(logger),
    ]
    for validator in validators:
        registry.register_validator(validator)
    return MpicAgent(
        logger,
        registry,
        eligible_types=eligible_types,
        use_local_resolver=use_local_resolver,
    )
