# pylint: disable=R0913, R0917
"""
Remote-agent network perspective (MPIC method 3a, client side).

A :class:`RemoteAgentPerspective` delegates validation to a self-hosted agent
running in a distinct network location. The agent runs the same validator
against the forwarded :class:`ChallengeContext` and returns the result over an
mTLS-protected HTTP call (see :mod:`.protocol`).

Perspective identity (name / country / ASN) is taken from local configuration,
never from the agent's response, so a compromised or misconfigured agent cannot
misrepresent which perspective it is.
"""

from typing import Any, List, Optional
import logging

import requests

from ..base import ChallengeContext
from .perspective import PerspectiveMetadata, PerspectiveResult, RemotePerspective
from .protocol import (
    MPIC_VALIDATE_PATH,
    context_to_payload,
    payload_to_validation_result,
)


class RemoteAgentPerspective(RemotePerspective):
    """A perspective backed by a remote validation agent."""

    def __init__(
        self,
        logger: logging.Logger,
        metadata: PerspectiveMetadata,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        ca_bundle: Optional[str] = None,
        timeout: int = 10,
    ):
        super().__init__(logger, metadata, is_primary=False)
        self.timeout = timeout
        # requests client-cert tuple for mutual TLS (None -> no client cert)
        if client_cert and client_key:
            self.client_cert = (client_cert, client_key)
        elif client_cert:
            self.client_cert = client_cert
        else:
            self.client_cert = None
        # verify server cert against the agent CA bundle when provided
        self.verify = ca_bundle if ca_bundle else True

    def validate(
        self, challenge_type: str, context: ChallengeContext
    ) -> PerspectiveResult:
        self.logger.debug(
            "RemoteAgentPerspective.validate(%s) via %s",
            challenge_type,
            self.metadata.url,
        )

        def _run() -> PerspectiveResult:
            url = (self.metadata.url or "").rstrip("/") + MPIC_VALIDATE_PATH
            response = requests.post(
                url,
                json={
                    "challenge_type": challenge_type,
                    "context": context_to_payload(context),
                },
                cert=self.client_cert,
                verify=self.verify,
                timeout=self.timeout,
            )
            response.raise_for_status()
            result = payload_to_validation_result(response.json())
            return PerspectiveResult(
                perspective_name=self.name,
                is_primary=False,
                success=result.success,
                invalid=result.invalid,
                error_message=result.error_message,
                evidence=result.details,
                metadata=self.metadata,
            )

        return self._timed(_run)


def build_remote_perspectives(
    logger: logging.Logger, config: Any
) -> List[RemotePerspective]:
    """Construct remote perspectives from configuration.

    ``config.mpic_perspectives`` is a list of dicts with at least ``name`` and
    ``url``; ``region``/``country``/``asn`` are optional declared metadata.
    Entries missing ``name`` or ``url`` are skipped with a warning.
    """
    logger.debug("mpic.build_remote_perspectives()")
    perspectives: List[RemotePerspective] = []
    entries = getattr(config, "mpic_perspectives", None) or []

    client_cert = getattr(config, "mpic_client_cert", None)
    client_key = getattr(config, "mpic_client_key", None)
    ca_bundle = getattr(config, "mpic_ca_bundle", None)
    timeout = getattr(config, "mpic_perspective_timeout", 10)

    for entry in entries:
        if not isinstance(entry, dict):
            logger.warning("mpic perspective entry is not a mapping: %r", entry)
            continue
        name = entry.get("name")
        url = entry.get("url")
        if not name or not url:
            logger.warning(
                "mpic perspective entry missing name or url, skipping: %r", entry
            )
            continue
        metadata = PerspectiveMetadata(
            name=name,
            url=url,
            region=entry.get("region"),
            country=entry.get("country"),
            asn=entry.get("asn"),
        )
        perspectives.append(
            RemoteAgentPerspective(
                logger,
                metadata,
                client_cert=client_cert,
                client_key=client_key,
                ca_bundle=ca_bundle,
                timeout=timeout,
            )
        )

    logger.debug(
        "mpic.build_remote_perspectives() ended with %d perspective(s)",
        len(perspectives),
    )
    return perspectives
