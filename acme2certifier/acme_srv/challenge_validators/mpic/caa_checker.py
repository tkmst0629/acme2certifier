"""
CAA checker for Multi-Perspective Issuance Corroboration.

Implements a CAA (Certification Authority Authorization) policy check suitable
for running as a corroboration unit from multiple perspectives. It plugs into
the same machinery as the DCV validators by implementing the
:class:`ChallengeValidator` interface with challenge type ``caa``: a corroborating
result (``success``) means "CAA permits this issuer to issue for the identifier".

Scope / correctness notes:

* RFC 8659 tree-climbing to locate the relevant CAA record set; empty tree =>
  issuance permitted; a present set with no applicable ``issue``/``issuewild``
  => permitted; a critical (issuer-critical flag) unknown property => refused.
* Wildcard requests use ``issuewild`` when present, else fall back to ``issue``.
* RFC 8657 ``accounturi`` / ``validationmethods`` parameters are honoured.
* Lookup failures (SERVFAIL/timeout) are treated as **fail-closed**
  (non-corroborating) so a broken/hijacked resolver cannot yield a false allow.
* DNSSEC validation is delegated to the resolver; this code does not validate
  signatures itself.
"""

from typing import Any, Dict, List, Optional, Tuple
import logging

import dns.exception
import dns.resolver

from ..base import ChallengeValidator, ChallengeContext, ValidationResult

_ISSUER_CRITICAL = 0x80
_KNOWN_TAGS = ("issue", "issuewild", "iodef")


def caa_rrset_get(
    logger: logging.Logger, fqdn: str, dns_srv: Optional[List[str]] = None
) -> Tuple[Optional[List[Dict[str, Any]]], bool]:
    """Locate the relevant CAA record set by RFC 8659 tree-climbing.

    Returns ``(records, error)``:
    * ``([...], False)`` -- the first ancestor with a CAA RRset (may match at the
      FQDN itself),
    * ``([], False)``   -- no CAA records anywhere in the tree (issuance allowed),
    * ``(None, True)``  -- a lookup error occurred (caller must fail closed).
    """
    logger.debug("caa_rrset_get(%s)", fqdn)
    if dns_srv:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = dns_srv
        resolve = resolver.resolve
    else:
        resolve = dns.resolver.resolve

    labels = fqdn.rstrip(".").split(".")
    # climb from the FQDN up to the registerable-ish domain (last two labels)
    for idx in range(len(labels) - 1):
        name = ".".join(labels[idx:])
        try:
            answer = resolve(name, "CAA")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as err:
            logger.error("caa_rrset_get(): lookup error for %s: %s", name, err)
            return None, True
        except Exception as err:  # noqa: BLE001 - fail closed on anything else
            logger.error("caa_rrset_get(): unexpected error for %s: %s", name, err)
            return None, True

        records = []
        for rrecord in answer:
            tag = rrecord.tag
            value = rrecord.value
            records.append(
                {
                    "flags": int(rrecord.flags),
                    "tag": tag.decode() if isinstance(tag, bytes) else str(tag),
                    "value": (
                        value.decode() if isinstance(value, bytes) else str(value)
                    ),
                }
            )
        if records:
            return records, False

    return [], False


def _parse_issue_value(value: str) -> Tuple[str, Dict[str, str]]:
    """Parse an issue/issuewild value into (issuer-domain, parameters)."""
    parts = value.split(";")
    domain = parts[0].strip()
    params: Dict[str, str] = {}
    for chunk in parts[1:]:
        if "=" in chunk:
            key, val = chunk.split("=", 1)
            params[key.strip().lower()] = val.strip()
    return domain, params


def _issuer_matches(domain: str, issuer_identities: List[str]) -> bool:
    """True when the issue value's domain names one of our issuer identities."""
    domain = domain.rstrip(".").lower()
    return any(domain == (i or "").rstrip(".").lower() for i in issuer_identities)


def _params_ok(
    params: Dict[str, str],
    account_uri: Optional[str],
    validation_method: Optional[str],
) -> bool:
    """Honour RFC 8657 accounturi / validationmethods restrictions."""
    if "accounturi" in params:
        if not account_uri or params["accounturi"] != account_uri:
            return False
    if "validationmethods" in params:
        allowed = [m.strip() for m in params["validationmethods"].split(",") if m]
        if not validation_method or validation_method not in allowed:
            return False
    return True


def caa_permits(
    records: List[Dict[str, Any]],
    issuer_identities: List[str],
    is_wildcard: bool = False,
    account_uri: Optional[str] = None,
    validation_method: Optional[str] = None,
) -> bool:
    """Decide whether the relevant CAA record set permits our issuance."""
    if not records:
        return True  # no CAA records in the tree -> unrestricted

    # issuer-critical unknown property -> must not issue (RFC 8659)
    for rec in records:
        if rec["flags"] & _ISSUER_CRITICAL and rec["tag"] not in _KNOWN_TAGS:
            return False

    issue = [r for r in records if r["tag"] == "issue"]
    issuewild = [r for r in records if r["tag"] == "issuewild"]
    applicable = issuewild if (is_wildcard and issuewild) else issue

    if not applicable:
        # only iodef (or nothing relevant) present -> issuance permitted
        return True

    for rec in applicable:
        domain, params = _parse_issue_value(rec["value"])
        if domain == "":
            continue  # ';' explicitly forbids issuance
        if _issuer_matches(domain, issuer_identities) and _params_ok(
            params, account_uri, validation_method
        ):
            return True
    return False


class CaaChecker(ChallengeValidator):
    """Runs a CAA policy check as an MPIC corroboration unit (type ``caa``)."""

    def get_challenge_type(self) -> str:
        return "caa"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        self.logger.debug("CaaChecker.perform_validation()")
        options = context.options or {}
        issuer_identities = options.get("issuer_domain_names") or []
        account_uri = options.get("accounturi")
        validation_method = options.get("validation_method")

        identifier = context.authorization_value or ""
        is_wildcard = identifier.startswith("*.")
        fqdn = identifier[2:] if is_wildcard else identifier

        records, error = caa_rrset_get(self.logger, fqdn, context.dns_servers)
        if error:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message="CAA lookup error (fail-closed)",
                details={"caa_error": True, "fqdn": fqdn},
            )

        permitted = caa_permits(
            records,
            issuer_identities,
            is_wildcard=is_wildcard,
            account_uri=account_uri,
            validation_method=validation_method,
        )
        if not permitted:
            self.logger.warning(
                "CAA check forbids issuance: fqdn=%s issuers=%s records=%s",
                fqdn,
                issuer_identities,
                records,
            )
        return ValidationResult(
            success=permitted,
            invalid=not permitted,
            error_message=(
                None
                if permitted
                else '{"status": 403, "type": '
                '"urn:ietf:params:acme:error:caa", '
                '"detail": "CAA record forbids issuance"}'
            ),
            details={
                "fqdn": fqdn,
                "is_wildcard": is_wildcard,
                "issuer_identities": issuer_identities,
                "caa_records": records,
                "permitted": permitted,
            },
        )
