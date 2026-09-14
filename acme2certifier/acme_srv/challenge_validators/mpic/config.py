"""
Shared MPIC configuration parsing.

The MPIC settings live in the ``[Challenge]`` section and are consumed by more
than one component (challenge validation and, when acme2certifier is the
issuing CA, the CAA check at order finalize). Parsing them in one place keeps
those consumers from drifting apart.
"""

from configparser import ConfigParser
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
import logging

_VALID_ENFORCEMENT = ("monitor", "enforce")
_VALID_PROVIDERS = ("self_hosted", "open_mpic")


@dataclass
class MpicConfig:
    """Parsed MPIC settings (field names match the configuration keys)."""

    mpic_enabled: bool = False
    mpic_enforcement: str = "enforce"
    mpic_min_remote_perspectives: int = 3
    mpic_perspective_timeout: int = 10
    mpic_min_distinct_regions: int = 1
    mpic_perspectives: Optional[List[Dict[str, str]]] = None
    mpic_client_cert: Optional[str] = None
    mpic_client_key: Optional[str] = None
    mpic_ca_bundle: Optional[str] = None
    mpic_provider: str = "self_hosted"
    mpic_provider_url: Optional[str] = None
    mpic_provider_api_key: Optional[str] = None
    mpic_provider_token: Optional[str] = None
    mpic_provider_perspective_count: Optional[int] = None
    mpic_provider_quorum_count: Optional[int] = None
    caaidentities: List[str] = field(default_factory=list)


def _int_load(
    logger: logging.Logger, config_dic: ConfigParser, key: str, fallback: int
) -> int:
    """Parse an integer option, warning and keeping the fallback on error."""
    raw = config_dic.get("Challenge", key, fallback=None)
    if raw is None:
        return fallback
    try:
        return int(raw)
    except Exception as err_:
        logger.warning("Failed to parse %s from configuration: %s", key, err_)
        return fallback


def _perspectives_load(
    logger: logging.Logger, config_dic: ConfigParser
) -> Optional[List[Dict[str, str]]]:
    """Parse the JSON list of remote perspectives."""
    raw = config_dic.get("Challenge", "mpic_perspectives", fallback=None)
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except Exception as err_:
        logger.warning("Failed to parse mpic_perspectives from configuration: %s", err_)
        return None
    if not isinstance(parsed, list):
        logger.warning(
            "mpic_perspectives must be a JSON array, got: %s", type(parsed).__name__
        )
        return None
    return parsed


def _provider_load(
    logger: logging.Logger, config_dic: ConfigParser, cfg: MpicConfig
) -> None:
    """Parse the external-provider settings into ``cfg``."""
    provider = (
        config_dic.get("Challenge", "mpic_provider", fallback="self_hosted")
        .strip()
        .lower()
    )
    if provider not in _VALID_PROVIDERS:
        logger.warning(
            "Invalid mpic_provider %r, falling back to 'self_hosted'", provider
        )
        provider = "self_hosted"
    cfg.mpic_provider = provider
    if provider != "open_mpic":
        return

    cfg.mpic_provider_url = config_dic.get(
        "Challenge", "mpic_provider_url", fallback=None
    )
    if not cfg.mpic_provider_url:
        logger.warning("mpic_provider is 'open_mpic' but mpic_provider_url is not set")
    cfg.mpic_provider_api_key = config_dic.get(
        "Challenge", "mpic_provider_api_key", fallback=None
    )
    cfg.mpic_provider_token = config_dic.get(
        "Challenge", "mpic_provider_token", fallback=None
    )
    for key in ("mpic_provider_perspective_count", "mpic_provider_quorum_count"):
        raw = config_dic.get("Challenge", key, fallback=None)
        if raw is not None:
            try:
                setattr(cfg, key, int(raw))
            except Exception as err_:
                logger.warning("Failed to parse %s from configuration: %s", key, err_)


def caaidentities_load(logger: logging.Logger, config_dic: ConfigParser) -> List[str]:
    """Load ``Directory.caaidentities`` (the CA's own CAA identities)."""
    raw = config_dic.get("Directory", "caaidentities", fallback=None)
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
    except Exception:
        pass
    logger.warning(
        "Failed to parse caaidentities from configuration, expected JSON array. Got: %s",
        raw,
    )
    return [raw]


def mpic_config_load(logger: logging.Logger, config_dic: ConfigParser) -> MpicConfig:
    """Parse all MPIC settings from the ``[Challenge]`` section."""
    logger.debug("mpic.mpic_config_load()")
    cfg = MpicConfig()
    cfg.mpic_enabled = config_dic.getboolean(
        "Challenge", "mpic_enabled", fallback=False
    )
    if not cfg.mpic_enabled:
        return cfg

    enforcement = (
        config_dic.get("Challenge", "mpic_enforcement", fallback="enforce")
        .strip()
        .lower()
    )
    if enforcement not in _VALID_ENFORCEMENT:
        logger.warning(
            "Invalid mpic_enforcement %r, falling back to 'enforce'", enforcement
        )
        enforcement = "enforce"
    cfg.mpic_enforcement = enforcement

    cfg.mpic_min_remote_perspectives = _int_load(
        logger, config_dic, "mpic_min_remote_perspectives", 3
    )
    cfg.mpic_perspective_timeout = _int_load(
        logger, config_dic, "mpic_perspective_timeout", 10
    )
    cfg.mpic_min_distinct_regions = _int_load(
        logger, config_dic, "mpic_min_distinct_regions", 1
    )
    cfg.mpic_perspectives = _perspectives_load(logger, config_dic)
    cfg.mpic_client_cert = config_dic.get(
        "Challenge", "mpic_client_cert", fallback=None
    )
    cfg.mpic_client_key = config_dic.get("Challenge", "mpic_client_key", fallback=None)
    cfg.mpic_ca_bundle = config_dic.get("Challenge", "mpic_ca_bundle", fallback=None)
    _provider_load(logger, config_dic, cfg)
    cfg.caaidentities = caaidentities_load(logger, config_dic)

    logger.debug("mpic.mpic_config_load() ended (provider=%s)", cfg.mpic_provider)
    return cfg
