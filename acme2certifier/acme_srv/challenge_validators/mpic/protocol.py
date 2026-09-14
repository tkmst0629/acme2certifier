"""
Wire protocol shared by the MPIC coordinator (client) and remote agent (server).

Keeping (de)serialization in one place means the client that calls a remote
perspective and the agent service that answers it cannot drift apart.

The agent exposes ``POST {MPIC_VALIDATE_PATH}`` and expects::

    { "challenge_type": "dns-01", "context": { ...context payload... } }

and answers with a validation-result payload::

    { "success": bool, "invalid": bool,
      "error_message": str|null, "details": {...} }
"""

from typing import Any, Dict

from ..base import ChallengeContext, ValidationResult

MPIC_VALIDATE_PATH = "/mpic/validate"

# Challenge types eligible for Multi-Perspective Issuance Corroboration.
# MPIC applies to all domain-control-validation methods (BR 3.2.2.9).
MPIC_CHALLENGE_TYPES = ("http-01", "dns-01", "tls-alpn-01")

# Context fields carried to a remote perspective. Only JSON-serialisable fields
# a validator needs to reproduce ``perform_validation`` are included.
_CONTEXT_FIELDS = (
    "challenge_name",
    "token",
    "jwk_thumbprint",
    "authorization_type",
    "authorization_value",
    "keyauthorization",
    "dns_servers",
    "proxy_servers",
    "timeout",
    "source_address",
    "options",
)


def context_to_payload(context: ChallengeContext) -> Dict[str, Any]:
    """Serialise a :class:`ChallengeContext` into a JSON-safe dict."""
    return {field: getattr(context, field, None) for field in _CONTEXT_FIELDS}


def payload_to_context(payload: Dict[str, Any]) -> ChallengeContext:
    """Rebuild a :class:`ChallengeContext` from a request payload."""
    optional = {
        field: payload.get(field)
        for field in _CONTEXT_FIELDS
        if field
        not in (
            "challenge_name",
            "token",
            "jwk_thumbprint",
            "authorization_type",
            "authorization_value",
            "timeout",
        )
    }
    # timeout has a non-None default on the dataclass; only pass it when given
    if payload.get("timeout") is not None:
        optional["timeout"] = payload["timeout"]
    return ChallengeContext(
        challenge_name=payload.get("challenge_name") or "",
        token=payload.get("token") or "",
        jwk_thumbprint=payload.get("jwk_thumbprint") or "",
        authorization_type=payload.get("authorization_type") or "dns",
        authorization_value=payload.get("authorization_value") or "",
        **optional,
    )


def validation_result_to_payload(result: ValidationResult) -> Dict[str, Any]:
    """Serialise a :class:`ValidationResult` for an agent response."""
    return {
        "success": bool(result.success),
        "invalid": bool(result.invalid),
        "error_message": result.error_message,
        "details": result.details,
    }


def payload_to_validation_result(payload: Dict[str, Any]) -> ValidationResult:
    """Parse an agent response payload into a :class:`ValidationResult`."""
    return ValidationResult(
        success=bool(payload.get("success", False)),
        invalid=bool(payload.get("invalid", True)),
        error_message=payload.get("error_message"),
        details=payload.get("details"),
    )
