"""
MPIC coordinator.

Fans validation out to the Primary (local) perspective plus any configured
remote perspectives, collects their results in parallel, applies the
:class:`QuorumPolicy`, and returns a single :class:`ValidationResult` whose
``details`` carry the per-perspective evidence needed for the audit trail.
"""

from typing import List, Optional
import logging

from ...threadwithreturnvalue import ThreadWithReturnValue
from ..base import ChallengeContext, ChallengeValidator, ValidationResult
from .perspective import LocalPerspective, PerspectiveResult, RemotePerspective
from .quorum import EnforcementMode, QuorumDecision, QuorumPolicy

INCORRECT_RESPONSE = (
    '{"status": 403, "type": "urn:ietf:params:acme:error:incorrectResponse", '
    '"detail": "Multi-perspective corroboration failed: %s"}'
)


class MpicCoordinator:
    """Coordinates multi-perspective corroboration for a single challenge."""

    def __init__(
        self,
        logger: logging.Logger,
        policy: QuorumPolicy,
        remote_perspectives: Optional[List[RemotePerspective]] = None,
        perspective_timeout: int = 10,
    ):
        self.logger = logger
        self.policy = policy
        self.remote_perspectives = list(remote_perspectives or [])
        self.perspective_timeout = perspective_timeout

    def corroborate(
        self,
        challenge_type: str,
        context: ChallengeContext,
        validator: ChallengeValidator,
    ) -> ValidationResult:
        """Validate ``challenge_type`` across all perspectives and apply quorum."""
        self.logger.debug(
            "MpicCoordinator.corroborate(%s) with %d remote perspective(s)",
            challenge_type,
            len(self.remote_perspectives),
        )

        perspectives: List[RemotePerspective] = [
            LocalPerspective(self.logger, validator)
        ] + self.remote_perspectives

        results = self._fan_out(challenge_type, context, perspectives)
        decision = self.policy.evaluate(results)
        allowed = self.policy.is_issuance_allowed(decision, self.logger)

        self._log_decision(challenge_type, context, decision, allowed)

        error_message = None
        if not allowed:
            error_message = INCORRECT_RESPONSE % (
                "; ".join(decision.reasons) or "quorum not met"
            )

        return ValidationResult(
            success=allowed,
            invalid=not allowed,
            error_message=error_message,
            details={
                "mpic": self._decision_details(decision),
                "perspectives": [self._result_details(r) for r in results],
            },
        )

    def _fan_out(
        self,
        challenge_type: str,
        context: ChallengeContext,
        perspectives: List[RemotePerspective],
    ) -> List[PerspectiveResult]:
        """Run every perspective in parallel and collect their results."""
        threads = []
        for perspective in perspectives:
            thread = ThreadWithReturnValue(
                target=perspective.validate,
                args=(challenge_type, context),
            )
            thread.daemon = True
            thread.start()
            threads.append((perspective, thread))

        results: List[PerspectiveResult] = []
        for perspective, thread in threads:
            result = thread.join(timeout=self.perspective_timeout)
            if result is None:
                # timed out or thread returned nothing -- treat as non-corroborating
                self.logger.warning(
                    "MPIC perspective %s timed out after %ss",
                    perspective.name,
                    self.perspective_timeout,
                )
                result = PerspectiveResult(
                    perspective_name=perspective.name,
                    is_primary=perspective.is_primary,
                    success=False,
                    invalid=True,
                    error_message="perspective timed out",
                    metadata=perspective.metadata,
                )
            results.append(result)
        return results

    def _log_decision(
        self,
        challenge_type: str,
        context: ChallengeContext,
        decision: QuorumDecision,
        allowed: bool,
    ) -> None:
        """Emit a structured audit line for the corroboration outcome."""
        self.logger.info(
            "MPIC %s challenge=%s host=%s mode=%s decision=%s primary_ok=%s "
            "remote=%d corroborating=%d non_corroborating=%d allowed_non_corr=%d "
            "min_remote=%d reasons=%s",
            challenge_type,
            context.challenge_name,
            context.authorization_value,
            (
                self.policy.enforcement.value
                if isinstance(self.policy.enforcement, EnforcementMode)
                else self.policy.enforcement
            ),
            "allow" if allowed else "deny",
            decision.primary_ok,
            decision.remote_total,
            decision.remote_corroborating,
            decision.remote_non_corroborating,
            decision.allowed_non_corroborating,
            decision.min_remote_required,
            "; ".join(decision.reasons) or "none",
        )

    @staticmethod
    def _decision_details(decision: QuorumDecision) -> dict:
        return {
            "compliant": decision.compliant,
            "primary_ok": decision.primary_ok,
            "remote_total": decision.remote_total,
            "remote_corroborating": decision.remote_corroborating,
            "remote_non_corroborating": decision.remote_non_corroborating,
            "allowed_non_corroborating": decision.allowed_non_corroborating,
            "min_remote_required": decision.min_remote_required,
            "reasons": decision.reasons,
        }

    @staticmethod
    def _result_details(result: PerspectiveResult) -> dict:
        meta = result.metadata
        return {
            "name": result.perspective_name,
            "is_primary": result.is_primary,
            "corroborates": result.corroborates,
            "success": result.success,
            "invalid": result.invalid,
            "error_message": result.error_message,
            "elapsed_ms": result.elapsed_ms,
            "region": meta.region if meta else None,
            "country": meta.country if meta else None,
            "asn": meta.asn if meta else None,
        }
