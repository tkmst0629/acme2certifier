# pylint: disable=R0913, R0917
"""
External MPIC provider adapter (method 3b).

Delegates the *entire* corroboration to an Open MPIC-compatible service
(``POST /mpic``) instead of running acme2certifier's own coordinator/quorum.
The service performs the multi-perspective fan-out and quorum itself and returns
an ``is_valid`` verdict, which is mapped onto a :class:`ValidationResult`.

Reference API: https://github.com/open-mpic/open-mpic-specification
(single ``POST /mpic`` endpoint; auth via ``x-api-key`` or ``Authorization:
Bearer``; request carries ``domain_or_ip_target`` + ``validation_method`` +
challenge material; response carries ``is_valid`` and per-``perspectives``).

Because the verdict is produced remotely, this adapter exposes the same
``corroborate()`` entry point as :class:`MpicCoordinator` but does not use the
local :class:`QuorumPolicy`. In ``monitor`` mode it still runs the local
single-perspective validator to gate issuance and only *observes* the external
result (rollout behaviour); in ``enforce`` mode the external verdict decides.
"""

from typing import Any, Dict, Optional
import logging

import requests

from ..base import ChallengeContext, ChallengeValidator, ValidationResult
from .quorum import EnforcementMode

MPIC_ENDPOINT_PATH = "/mpic"

# acme2certifier challenge type -> Open MPIC validation_method (DCV)
_METHOD_MAP = {
    "dns-01": "acme-dns-01",
    "http-01": "acme-http-01",
    "tls-alpn-01": "acme-tls-alpn-01",
}
CAA_CHECK_TYPE = "caa"

INCORRECT_RESPONSE = (
    '{"status": 403, "type": "urn:ietf:params:acme:error:incorrectResponse", '
    '"detail": "External MPIC corroboration failed: %s"}'
)


class ExternalMpicProvider:
    """Delegates corroboration to an Open MPIC-compatible service."""

    def __init__(
        self,
        logger: logging.Logger,
        url: str,
        api_key: Optional[str] = None,
        token: Optional[str] = None,
        enforcement: EnforcementMode = EnforcementMode.ENFORCE,
        timeout: int = 10,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        ca_bundle: Optional[str] = None,
        perspective_count: Optional[int] = None,
        quorum_count: Optional[int] = None,
    ):
        self.logger = logger
        self.url = (url or "").rstrip("/") + MPIC_ENDPOINT_PATH
        self.api_key = api_key
        self.token = token
        self.enforcement = enforcement
        self.timeout = timeout
        if client_cert and client_key:
            self.client_cert = (client_cert, client_key)
        elif client_cert:
            self.client_cert = client_cert
        else:
            self.client_cert = None
        self.verify = ca_bundle if ca_bundle else True
        self.perspective_count = perspective_count
        self.quorum_count = quorum_count

    def corroborate(
        self,
        challenge_type: str,
        context: ChallengeContext,
        validator: ChallengeValidator,
    ) -> ValidationResult:
        """Corroborate ``challenge_type`` via the external MPIC service."""
        self.logger.debug("ExternalMpicProvider.corroborate(%s)", challenge_type)

        if self.enforcement == EnforcementMode.MONITOR:
            # gate on the local single-perspective result; only observe MPIC
            local = validator.validate_challenge(context)
            external = self._query(challenge_type, context)
            self._log(challenge_type, context, external, blocking=False)
            details = {"mpic_provider": "open_mpic", "observed": external}
            if local.details:
                details["local"] = local.details
            return ValidationResult(
                success=local.success,
                invalid=local.invalid,
                error_message=local.error_message,
                details=details,
            )

        # enforce: the external verdict decides
        external = self._query(challenge_type, context)
        self._log(challenge_type, context, external, blocking=True)
        allowed = bool(external.get("is_valid")) and not external.get("error")
        error_message = None
        if not allowed:
            reason = external.get("error") or "quorum not met"
            error_message = INCORRECT_RESPONSE % reason
        return ValidationResult(
            success=allowed,
            invalid=not allowed,
            error_message=error_message,
            details={"mpic_provider": "open_mpic", "response": external},
        )

    def _query(self, challenge_type: str, context: ChallengeContext) -> Dict[str, Any]:
        """POST the corroboration request; never raises (errors are captured)."""
        try:
            body = self._build_request(challenge_type, context)
        except Exception as err:  # noqa: BLE001
            self.logger.error("ExternalMpicProvider: cannot build request: %s", err)
            return {"is_valid": False, "error": f"request build failed: {err}"}

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            response = requests.post(
                self.url,
                json=body,
                headers=headers,
                cert=self.client_cert,
                verify=self.verify,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as err:  # noqa: BLE001 - isolate transport failures
            self.logger.error("ExternalMpicProvider: request failed: %s", err)
            return {"is_valid": False, "error": str(err)}

    def _build_request(
        self, challenge_type: str, context: ChallengeContext
    ) -> Dict[str, Any]:
        """Build the Open MPIC request body for a challenge."""
        # imported lazily to avoid heavy imports at module load time
        from acme2certifier.acme_srv.helper import (  # pylint: disable=import-outside-toplevel
            b64_url_encode,
            sha256_hash,
        )

        raw_target = context.authorization_value or ""
        is_wildcard = raw_target.startswith("*.")
        target = raw_target[2:] if is_wildcard else raw_target

        if challenge_type == CAA_CHECK_TYPE:
            body = self._build_caa_request(target, is_wildcard, context)
            self._add_orchestration(body)
            return body

        method = _METHOD_MAP.get(challenge_type)
        if not method:
            raise ValueError(f"unsupported challenge_type: {challenge_type}")

        key_authorization = (
            context.keyauthorization or f"{context.token}.{context.jwk_thumbprint}"
        )

        body: Dict[str, Any] = {
            "domain_or_ip_target": target,
            "validation_method": method,
        }
        if challenge_type == "http-01":
            body["token"] = context.token
            body["key_authorization"] = key_authorization
        else:  # dns-01 / tls-alpn-01 use the hashed key authorization
            body["key_authorization_hash"] = b64_url_encode(
                self.logger, sha256_hash(self.logger, key_authorization)
            )

        self._add_orchestration(body)
        return body

    @staticmethod
    def _build_caa_request(
        target: str, is_wildcard: bool, context: ChallengeContext
    ) -> Dict[str, Any]:
        """Build an Open MPIC CAA (check_type=caa) request body."""
        options = context.options or {}
        caa_params: Dict[str, Any] = {
            "certificate_type": ("tls-server-wildcard" if is_wildcard else "tls-server")
        }
        issuers = options.get("issuer_domain_names")
        if issuers:
            caa_params["caa_domains"] = issuers
        return {
            "domain_or_ip_target": target,
            "check_type": CAA_CHECK_TYPE,
            "caa_check_parameters": caa_params,
        }

    def _add_orchestration(self, body: Dict[str, Any]) -> None:
        """Attach optional perspective/quorum orchestration parameters."""
        orchestration: Dict[str, Any] = {}
        if self.perspective_count is not None:
            orchestration["perspective_count"] = self.perspective_count
        if self.quorum_count is not None:
            orchestration["quorum_count"] = self.quorum_count
        if orchestration:
            body["orchestration_parameters"] = orchestration

    def _log(
        self,
        challenge_type: str,
        context: ChallengeContext,
        external: Dict[str, Any],
        blocking: bool,
    ) -> None:
        """Emit an audit line for the external corroboration outcome."""
        self.logger.info(
            "MPIC-EXTERNAL %s challenge=%s host=%s mode=%s is_valid=%s error=%s",
            challenge_type,
            context.challenge_name,
            context.authorization_value,
            (
                self.enforcement.value
                if isinstance(self.enforcement, EnforcementMode)
                else self.enforcement
            ),
            external.get("is_valid"),
            external.get("error") or "none",
        )
        if not blocking and not external.get("is_valid"):
            self.logger.warning(
                "MPIC monitor mode: external MPIC did NOT corroborate "
                "(challenge=%s host=%s) -- issuance not blocked",
                context.challenge_name,
                context.authorization_value,
            )
