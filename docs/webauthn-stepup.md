# WebAuthn / passkey step-up authentication

The most destructive admin operations are gated behind a **second factor**: a
fresh FIDO2 passkey assertion, in addition to the operator's role. Knowing the
admin bearer token or holding an SSO session is not enough — the operator must
physically assert a registered authenticator (security key, platform
authenticator, or phone) at the moment of the action.

Protected operations (Task 161):

| Action | Endpoint |
| --- | --- |
| Break-glass quarantine approve / deny (Task 50) | `POST /admin/api/approvals/approve`, `.../deny` |
| Emergency lockdown engage / clear (Task 74) | `POST /admin/api/lockdown/engage`, `.../clear` |
| Apply a compliance policy preset (Task 88) | `POST /admin/api/presets/apply` |
| Trigger a credential / signing-key rotation (Task 148) | `POST /admin/api/keys/rotate` |

## How it works

1. **Enrolment** — an authenticated admin registers one or more passkeys from
   the **Passkeys** tab in the admin dashboard. The browser's WebAuthn
   `navigator.credentials.create()` ceremony runs; the proxy verifies the
   attestation statement (where the format permits), extracts the credential
   public key, and stores it (public key + signature counter) in a durable
   sidecar file keyed to the operator's SSO subject.
2. **Step-up** — when the operator invokes a protected action, the admin
   middleware returns `401` with an `X-StepUp-Required: webauthn` header. The
   dashboard transparently runs an assertion ceremony
   (`navigator.credentials.get()`), bound to that specific action, and retries
   the request with a short-lived `X-StepUp-Token` header. The proxy verifies
   the assertion signature against the stored credential key and admits the
   action.
3. **Audit** — every ceremony and every enforcement decision is recorded in the
   tamper-evident audit log as an `stepup_auth` event, attributable to the
   operator's identity.

Step-up requires the admin **SSO/RBAC** layer ([admin-sso-rbac.md](admin-sso-rbac.md))
so each ceremony binds to a real identity.

## Security properties

- **Replay-resistant challenges.** Each ceremony challenge is 32 bytes of CSPRNG
  output, bound to the operator and ceremony type, single-use, and expires after
  a short TTL (`webauthn.challengeTtl`, default 2m).
- **Single-use, short-TTL step-up tokens.** A successful assertion mints one
  token, bound to the subject and (optionally) the action, valid for
  `webauthn.stepUpTtl` (default 5m) and consumed on first use — it can never be
  replayed.
- **Signature-counter rollback detection.** The authenticator signature counter
  must strictly increase across assertions; a stale or equal counter signals a
  cloned authenticator and the assertion is rejected
  (`pullthrough_webauthn_counter_rollbacks_total`).
- **Origin & RP-ID binding.** The client-data origin must match the configured
  allowlist and the RP-ID hash must match on every ceremony.

## Configuration

```yaml
webauthn:
  enabled: true
  # enforce: true            # gate the protected endpoints (default true when enabled;
                             # set false to stage a rollout: ceremonies work, endpoints not yet gated)
  rpId: admin.example.com    # the effective registrable domain of the admin UI (required)
  rpName: "Acme Pullthrough Admin"
  origins:                   # at least one allowed WebAuthn origin (required)
    - https://admin.example.com
  requireUserVerification: true   # demand PIN/biometric, not just presence (default true)
  challengeTtl: 2m
  stepUpTtl: 5m
  allowUnverifiedAttestation: true  # accept attestation formats we can't cryptographically
                                    # check, flagged as unverified (default true)
  storePath: /var/lib/pullthrough/webauthn.json  # durable credential store
  # protectedActions:        # override the default set of step-up-gated admin API paths
  #   - /api/keys/rotate
```

See [configuration-reference.md](configuration-reference.md) for the full field
list and defaults.

### Rollout guidance

Enroll passkeys for every operator who performs a protected action **before**
turning on enforcement, otherwise they will be locked out of those actions until
they enroll. A safe sequence:

1. Set `webauthn.enabled: true` and `enforce: false`. Operators enroll from the
   Passkeys tab and can run the **Test step-up** button.
2. Once all operators have a passkey (`pullthrough_webauthn_enrolled_subjects`),
   set `enforce: true`.

## Metrics

All counters/gauges are exported under the `pullthrough_webauthn_` prefix:

| Metric | Meaning |
| --- | --- |
| `pullthrough_webauthn_registrations_total` | completed passkey enrolments |
| `pullthrough_webauthn_registration_failures_total` | failed registration ceremonies |
| `pullthrough_webauthn_assertions_total` | successful step-up assertions |
| `pullthrough_webauthn_assertion_failures_total` | failed assertions |
| `pullthrough_webauthn_counter_rollbacks_total` | signature-counter regressions (cloned authenticator) |
| `pullthrough_webauthn_challenges_issued_total` | challenges minted |
| `pullthrough_webauthn_challenges_expired_total` | ceremonies rejected for an unknown/expired challenge |
| `pullthrough_webauthn_stepup_required_total` | protected requests that demanded a token |
| `pullthrough_webauthn_stepup_verified_total` | protected requests admitted by a fresh assertion |
| `pullthrough_webauthn_stepup_denied_total` | protected requests blocked for a missing/invalid token |
| `pullthrough_webauthn_active_credentials` | registered credentials (gauge) |
| `pullthrough_webauthn_enrolled_subjects` | identities with ≥1 passkey (gauge) |
| `pullthrough_webauthn_pending_challenges` | outstanding un-consumed challenges (gauge) |

## Supported algorithms

Registration advertises, and the verifier accepts, **ES256** (ECDSA P-256),
**EdDSA** (Ed25519), and **RS256** (RSA PKCS#1 v1.5). Attestation statement
verification covers the `none` and `packed` (self and x5c) formats; other
formats are accepted and flagged as unverified when
`allowUnverifiedAttestation` is true (the trust anchor at enrolment is the
authenticated admin session, not a manufacturer attestation CA).
