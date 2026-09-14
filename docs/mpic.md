<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Multi-Perspective Issuance Corroboration (MPIC) -->
# Multi-Perspective Issuance Corroboration (MPIC) — Design

> Status: method 3a — self-hosted distributed perspectives.
> Tracking branch: `feature/dns-multi-perspective-validation`.
>
> Implemented so far:
>
> * PR1 — coordination core: `RemotePerspective` / `LocalPerspective`,
>   `QuorumPolicy`, `MpicCoordinator`, and registry routing, gated behind
>   `mpic_enabled` (default `False`, i.e. a no-op).
> * PR2 — remote-agent client: `RemoteAgentPerspective` (mTLS HTTP client), the
>   shared wire protocol (`protocol.py`), config parsing for `mpic_perspectives`
>   and the mTLS credentials, and perspective-set construction.
> * PR3 — remote-agent service: `MpicAgent` + `agent_wsgi` (`POST /mpic/validate`
>   with bearer-token auth and optional client-cert-header enforcement), the
>   `a2c-mpic-agent` dev runner, and a deployment example under
>   [`examples/mpic/`](../examples/mpic).
> * PR4 — enforcement & observability: a network-diversity guard
>   (`mpic_min_distinct_regions`), a machine-readable `MPIC-AUDIT` JSON record
>   per issuance decision, and in-process metrics (`coordinator.stats`).
> * PR5 — external provider (method 3b): `ExternalMpicProvider` delegates the
>   whole corroboration to an Open MPIC-compatible `POST /mpic` service.
>   `mpic_provider = self_hosted | open_mpic` selects between the built-in
>   coordinator and the external service.
> * PR6 — **CAA corroboration** (section 10): `CaaChecker` (RFC 8659/8657,
>   fail-closed) plus `CaaCorroborator` run a CAA policy check across the same
>   MPIC handler as DCV. Agents serve the `caa` check type, and the external
>   provider maps it to Open MPIC's `check_type: caa`.
>
> End to end, either the built-in coordinator fans out over mTLS to self-hosted
> agents and applies the quorum/diversity policy, or the corroboration is
> delegated to an external Open MPIC service — both emit an audit trail, and
> both cover DCV **and** CAA.

## 1. Goal

Make domain control validation (DCV) corroborate results from multiple,
geographically and topologically distinct network perspectives before a
challenge is marked `valid`, as required by CA/Browser Forum Baseline
Requirements (BR) section 3.2.2.9 *Multi-Perspective Issuance Corroboration*.

MPIC applies to **all** validation methods (`http-01`, `dns-01`,
`tls-alpn-01`) and to CAA checks — not DNS only.

## 2. CA/B Forum requirements (BR 3.2.2.9) — reference

Quorum table (maximum tolerated non-corroborating perspectives):

| Distinct remote Network Perspectives used | Allowed non-corroborations |
| ----------------------------------------- | -------------------------- |
| 2 – 5                                     | 1                          |
| 6 or more                                 | 2                          |

Phased rollout:

| Effective      | Requirement                                                    |
| -------------- | ------------------------------------------------------------- |
| 2025-03-15     | Monitor with >= 2 remote perspectives (issuance not blocked)  |
| 2025-09-15     | Enforce quorum (block issuance on quorum failure)             |
| 2026-03-15     | >= 3 remote perspectives                                       |
| 2026-12-15     | >= 5 remote perspectives                                       |

Geographic / topology rule: for any pair of resolvers used in an MPIC
attempt, the straight-line distance between the State/Province/Country each
resides in MUST be >= 500 km; perspectives should also be network-diverse
(distinct RIR/AS where practical). These are **deployment** constraints; the
software cannot verify physical distance and only records/validates the
declared metadata.

> Note: MPIC is a *public-trust* CA requirement. For internal/private PKI it
> is out of scope; this feature is only meaningful when the operator actually
> deploys distributed perspectives that satisfy the constraints above.

## 3. Where MPIC plugs into acme2certifier

Current flow (unchanged parts in grey):

```
challenge.py
  -> builds ChallengeContext (dns_servers, proxy_servers, ...)
  -> ChallengeValidatorRegistry.validate_challenge(type, context)
       -> ChallengeValidator.validate_challenge(context)
            -> perform_validation(context)   # local network query
```

The unit of work a remote perspective must reproduce is exactly a validator's
`perform_validation(context)`. So a "perspective" is *a place that can run a
validator against a ChallengeContext and return a ValidationResult*.

MPIC inserts a **coordination layer** between the registry and the validator:

```
ChallengeValidatorRegistry.validate_challenge(type, context)
  -> if MPIC enabled for `type`:
        MpicCoordinator.corroborate(type, context, validator)
          -> fan-out to [LocalPerspective, RemoteAgent A, B, C, ...]
          -> collect PerspectiveResult[]  (parallel, with timeout)
          -> QuorumPolicy.decide(results)  -> aggregate ValidationResult
     else:
        validator.validate_challenge(context)   # existing path, unchanged
```

## 4. New abstractions

### 4.1 `RemotePerspective` (interface)

```python
class RemotePerspective(ABC):
    name: str
    metadata: PerspectiveMetadata  # region, country/state, rir/asn (declared)

    @abstractmethod
    def validate(self, challenge_type: str,
                 context: ChallengeContext) -> PerspectiveResult: ...
```

Implementations:

- `LocalPerspective` — runs the existing validator in-process. This is the
  **Primary Network Perspective**. With MPIC disabled (or a perspective list of
  just this one) behaviour is identical to today.
- `RemoteAgentPerspective` (method 3a) — mTLS HTTP client to a self-hosted
  validation agent (section 5).

Note that a `RemotePerspective` is a *single* perspective; the local
`MpicCoordinator` applies the quorum across several of them. An Open
MPIC-compatible service is a different shape — it performs the whole
corroboration (fan-out + quorum) and returns one `is_valid` verdict — so it is
integrated as a **provider** (`ExternalMpicProvider`, method 3b, section 6.1),
not a perspective. It exposes the same `corroborate()` entry point as the
coordinator but bypasses the local `QuorumPolicy`.

`PerspectiveResult` carries: `perspective_name`, `success`, `invalid`,
`error_message`, `evidence` (the validator `details`: resolved records/IPs,
TXT values, etc.), `metadata`, and timing — for audit logging.

### 4.2 `QuorumPolicy`

Encapsulates the BR table and phase rules:

- `min_remote_perspectives` (config; default tracks the current phase, e.g. 3)
- `max_non_corroboration(n_remote)` -> 1 for 2–5, 2 for 6+
- `decide(results) -> ValidationResult`:
  - require the Primary to succeed,
  - count corroborating vs non-corroborating **remote** perspectives,
  - fail if `#remote < min_remote_perspectives`,
  - fail if `#non_corroborating > max_non_corroboration(#remote)`.
- Optional `enforcement` = `monitor` | `enforce`
  (monitor logs the outcome but does not block issuance — mirrors the
  2025-03-15 → 2025-09-15 phase).

### 4.3 `MpicCoordinator`

- Builds the perspective set from config.
- Fans out `validate()` in parallel (reuse `ThreadWithReturnValue`) with
  per-perspective timeout.
- Feeds results to `QuorumPolicy` and produces one `ValidationResult` whose
  `details` includes every `PerspectiveResult` (for the audit trail).
- Diversity guard: warn/optionally fail if declared metadata does not meet
  500 km / AS-diversity policy.

## 5. Remote agent (method 3a)

A minimal, stateless service (`MpicAgent` + `agent_wsgi`) that runs the standard
DCV validators against a forwarded `ChallengeContext` and returns the result. It
registers only `http-01`/`dns-01`/`tls-alpn-01` and builds its registry with
MPIC disabled, so it performs plain single-perspective validation and never fans
out further. By default it validates from its own resolver
(`use_local_resolver: True` strips any resolver/proxy pinned in the request), so
each perspective genuinely queries from its own vantage point.

Contract:

```
POST /mpic/validate            (mTLS at the proxy + bearer token)
{ "challenge_type": "dns-01",
  "context": { authorization_value, token, jwk_thumbprint,
               authorization_type, ... } }
->
{ "success": bool, "invalid": bool,
  "error_message": str|null, "details": {...} }
```

Perspective identity (name/country/asn) is assigned by the coordinator from its
own configuration, not taken from the response, so a compromised agent cannot
claim to be a different perspective.

Security: bearer token (constant-time compared; `[MpicAgent] token` or
`MPIC_AGENT_TOKEN`) plus mutual TLS terminated at the reverse proxy, which
verifies the coordinator client certificate and passes `X-SSL-Client-Verify`
(enforced when `require_client_cert_header: True`). Agents keep no state.

### 5.1 Running an agent

```bash
# dev server (behind an mTLS-terminating proxy in production)
ACME_SRV_CONFIGFILE=agent.cfg MPIC_AGENT_TOKEN=... a2c-mpic-agent --port 8080
```

Or serve `acme2certifier.acme_srv.challenge_validators.mpic.agent_wsgi:application`
from uWSGI/gunicorn. A ready-made `docker-compose` + nginx (mTLS) topology is in
[`examples/mpic/`](../examples/mpic): `agent.cfg`, `nginx-agent.conf`,
`docker-compose.yml`.

Deployment: >= 3 agents (>= 5 from 2026-12-15) in distinct cloud
regions/providers, each pair >= 500 km apart, network-diverse.

### 5.2 Agent configuration (`[MpicAgent]` section)

| option | meaning | default |
| ------ | ------- | ------- |
| `token` | bearer secret the coordinator must present (`MPIC_AGENT_TOKEN` overrides) | *(none — all requests rejected)* |
| `use_local_resolver` | ignore forwarded resolver/proxy and validate from the agent's own resolver | `True` |
| `require_client_cert_header` | reject requests unless the proxy set `X-SSL-Client-Verify: SUCCESS` | `False` |

## 6. Configuration (acme_srv.yml, `Challenge` section — draft)

```ini
[Challenge]
mpic_enabled: True
mpic_enforcement: enforce          # monitor | enforce
mpic_min_remote_perspectives: 3
mpic_perspective_timeout: 10
# list of remote agents (self-hosted)
mpic_perspectives: [
  {"name":"tokyo",     "url":"https://a.example:8443", "country":"JP", "asn":"AS-x"},
  {"name":"frankfurt", "url":"https://b.example:8443", "country":"DE", "asn":"AS-y"},
  {"name":"virginia",  "url":"https://c.example:8443", "country":"US", "asn":"AS-z"}
]
mpic_client_cert: /path/mtls.crt
mpic_client_key:  /path/mtls.key
mpic_ca_bundle:   /path/agents-ca.pem
mpic_min_distinct_regions: 2       # network-diversity guard (1 = off)
```

Backward compatibility: `mpic_enabled` defaults to `False`. When disabled, the
existing single-perspective path runs untouched. `dns_server_list` keeps its
current meaning (resolver failover within a perspective).

### 6.1 External provider (Open MPIC, method 3b)

Set `mpic_provider: open_mpic` to delegate the whole corroboration to an
[Open MPIC](https://open-mpic.org/)-compatible service instead of running the
built-in coordinator. The service does the fan-out and quorum and returns
`is_valid`; the local `QuorumPolicy`/perspective settings are not used.

```ini
[Challenge]
mpic_enabled: True
mpic_provider: open_mpic
mpic_enforcement: enforce
mpic_provider_url: https://mpic.internal.example      # POST {url}/mpic
mpic_provider_api_key: <x-api-key secret>             # or mpic_provider_token (Bearer)
mpic_provider_perspective_count: 6                    # optional orchestration
mpic_provider_quorum_count: 5                         # optional orchestration
# mpic_client_cert / mpic_client_key / mpic_ca_bundle also apply to the TLS call
```

In `monitor` mode the local single-perspective validator still gates issuance
and the external verdict is only observed/logged (rollout behaviour); in
`enforce` mode the external `is_valid` decides. acme2certifier challenge types
map to Open MPIC `validation_method`s: `dns-01`→`acme-dns-01`,
`http-01`→`acme-http-01`, `tls-alpn-01`→`acme-tls-alpn-01`.

Open MPIC deploys as AWS Lambda (turnkey) or Docker containers; see
[open-mpic.org](https://open-mpic.org/) and the
[API specification](https://github.com/open-mpic/open-mpic-specification). The
IETF is standardising an MPIC service API
([draft-westerbaan-alldispatch-mpic](https://datatracker.ietf.org/doc/draft-westerbaan-alldispatch-mpic/));
`ExternalMpicProvider` should track it as it matures.

## 7. Observability / audit

Each issuance decision emits a machine-readable audit record as a single JSON
log line prefixed `MPIC-AUDIT`: challenge, identifier, enforcement mode, the
final decision, the computed quorum (including `distinct_regions`), and every
perspective's success/evidence/metadata/latency. This is the trail required to
demonstrate MPIC compliance during audits.

The coordinator also keeps in-process counters at `MpicCoordinator.stats`
(`attempts`, `allowed`, `denied`, `primary_failures`, and per-perspective
non-corroboration counts), exposed via `stats.as_dict()` for scraping without
adding a metrics dependency.

### 7.1 Network-diversity guard

`mpic_min_distinct_regions` requires the corroborating remote perspectives to
span at least that many distinct declared regions (country, else ASN, else
name). It is a proxy for the BR 500 km / topology requirement — the software
cannot measure physical distance — so correct placement remains an operator
responsibility. `1` (default) disables the check; set `2`+ for real MPIC.

## 8. Out of scope / caveats

- The software cannot verify physical 500 km separation or true AS diversity;
  it records declared metadata and enforces the policy on that metadata.
  Correct placement is an operator responsibility.
- CAA multi-perspective checking is implemented (section 10) but is **not yet
  wired into the issuance flow** — it is a component plus an API the operator
  calls. acme2certifier historically does not perform CAA checking at all
  (that is the issuing CA's duty); this matters only when a2c *is* the CA.

## 9. Delivery plan (PR breakdown)

1. **PR1 — Coordination core (no behaviour change).** `RemotePerspective`,
   `LocalPerspective`, `PerspectiveResult`, `QuorumPolicy`, `MpicCoordinator`;
   registry routes through the coordinator only when `mpic_enabled=True`
   (default `False`, so a no-op). Unit tests for the quorum table and policy.
2. **PR2 — Remote agent client.** `RemoteAgentPerspective` (mTLS HTTP client),
   config parsing for `mpic_perspectives`/auth, perspective-set construction.
   Tests with mocked agents. Still default off.
3. **PR3 — Remote agent service.** `POST /mpic/validate` endpoint (perspective
   mode) + authN; docker-compose multi-region example; deployment docs
   (500 km / AS diversity guidance).
4. **PR4 — Enforcement, phasing & observability.** `monitor`/`enforce` modes,
   structured audit logging, metrics; extend coverage to `http-01` and
   `tls-alpn-01`.
5. **PR5 — External provider adapter.** `ExternalMpicProvider` delegates the
   whole corroboration to an Open MPIC-compatible `POST /mpic` service, selected
   via `mpic_provider: open_mpic` (see section 6.1).
6. **PR6 — CAA corroboration.** `CaaChecker` + `CaaCorroborator` (section 10).

## 10. CAA corroboration

SC-067 requires **both** domain validation *and* CAA checks to be performed from
multiple network perspectives. CAA checking is the duty of whoever issues the
certificate: in a typical acme2certifier deployment that is the backend CA, and
a2c performs no CAA lookups at all. When a2c **is** the issuing CA, the CAA
check becomes its responsibility and must also be multi-perspective.

`caa` is modelled as an additional check type flowing through the same MPIC
machinery as DCV, so quorum, diversity and the audit trail apply unchanged:

```
CaaCorroborator.corroborate(identifier, issuer_identities, ...)
  -> <MPIC handler>.corroborate("caa", context, CaaChecker)
       self_hosted : LocalPerspective + remote agents each run CaaChecker
                     -> QuorumPolicy (quorum + diversity) -> allow/deny
       open_mpic   : POST /mpic  {check_type: "caa", caa_check_parameters: ...}
```

`CaaChecker` (`caa_checker.py`) implements the policy itself:

- RFC 8659 tree-climbing to the relevant CAA record set; no records anywhere =>
  permitted; a set without applicable `issue`/`issuewild` => permitted.
- Wildcard requests prefer `issuewild`, falling back to `issue`.
- An `issue`/`issuewild` value of `;` forbids issuance.
- An issuer-critical (flag `0x80`) property we do not recognise => refused.
- RFC 8657 `accounturi` and `validationmethods` parameters are honoured.
- Lookup failures (SERVFAIL/timeout) are **fail-closed** — a broken or hijacked
  resolver can never produce a false allow. DNSSEC validation is delegated to
  the resolver.

Usage (the component is deliberately *not* wired into the issuance flow yet):

```python
from acme2certifier.acme_srv.challenge_validators.mpic import build_caa_corroborator

corroborator = build_caa_corroborator(logger, config)
result = corroborator.corroborate(
    "www.example.com",
    issuer_identities=["ca.example"],          # your CA's CAA identity
    account_uri="https://acme.example/acct/1", # for RFC 8657 accounturi
    is_wildcard=False,
    validation_method="dns-01",
)
if not result.success:
    raise RuntimeError("CAA forbids issuance")
```

No new configuration is required: `build_caa_corroborator` reuses
`mpic_provider` and the perspective/provider settings, so CAA is corroborated by
the same agents (which serve the `caa` check type) or the same external service
as DCV.
