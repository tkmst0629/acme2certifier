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
>
> The agent *service* that answers `POST /mpic/validate` (PR3) is not yet
> present. Configure `mpic_perspectives` pointing at agents once PR3 is
> deployed; until then run in `monitor` mode.

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
- `ExternalMpicPerspective` (method 3b, optional/later) — adapter to an
  external MPIC service (e.g. Open MPIC) or provider API.

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

A minimal, stateless service that runs the *same* validator code against a
ChallengeContext and returns the result. Two deployment shapes:

- **a2c in "perspective mode"** — the existing image with a slim endpoint
  `POST /mpic/validate` enabled and the ACME/CA surface disabled.
- **standalone slim agent** — packages only `challenge_validators` + helpers.

Contract (draft):

```
POST /mpic/validate            (mTLS + bearer token)
{ "challenge_type": "dns-01",
  "context": { authorization_value, token, jwk_thumbprint,
               authorization_type, dns_servers?, ... } }
->
{ "success": bool, "invalid": bool, "error_message": str|null,
  "details": {...}, "perspective": { name, region, country, asn } }
```

Security: mutual TLS between coordinator and agents; short-lived bearer
token; agents accept requests only from the coordinator; no persistence.

Deployment: >= 3 agents (>= 5 from 2026-12-15) in distinct cloud
regions/providers, each pair >= 500 km apart, network-diverse. A
`docker-compose`/topology example ships with the agent.

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
```

Backward compatibility: `mpic_enabled` defaults to `False`. When disabled, the
existing single-perspective path runs untouched. `dns_server_list` keeps its
current meaning (resolver failover within a perspective).

## 7. Observability / audit

Each issuance decision logs a structured record: challenge, identifier,
per-perspective success/evidence/metadata/latency, computed quorum, and the
final decision. Required to demonstrate MPIC compliance during audits.

## 8. Out of scope / caveats

- The software cannot verify physical 500 km separation or true AS diversity;
  it records declared metadata and enforces the policy on that metadata.
  Correct placement is an operator responsibility.
- CAA multi-perspective checking is a follow-up once/if a2c performs CAA.

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
5. **PR5 (optional) — External provider adapter.** `ExternalMpicPerspective`
   for Open MPIC / third-party APIs as an alternative perspective type.
