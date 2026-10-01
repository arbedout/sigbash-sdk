# Transaction authorization

Transaction authorization lets you authorize an action against a key's
policy, hand the signed authorization to an external enforcer, and let any
party verify it offline. It is a distinct lane from [signing](signing.md) —
see "The three enforcement strengths" below for exactly where this lane
stands.

```typescript
// 1. Authorize an action (drives preflight, the WASM export, and issuance).
const authz = await client.authorizePSBT({
  keyId,
  psbtBase64,
  kmcJSON,                    // From getKey().kmcJSON
  network: 'signet',
  lifetimeSeconds: 900,       // Optional; default 900, range [1, 86400]
});

// 2. An enforcer — anywhere, offline — verifies the artifact against the
//    raw subject it is about to execute.
const verdict = await client.verifyAuthorization({
  authorization: authz,       // Or { rawArtifact, rawSignature }
  subject: psbtBytes,         // The EXACT raw PSBT bytes to be executed
  network: 'signet',
  issuerKeySet,               // Pinned issuer key set (see below)
  salt,                       // The client-held policy salt (see "Salt secrecy")
  credential: { credentialIdentifier: authHashHex, keyIndex: 0 },
  now: Math.floor(Date.now() / 1000),
});
if (!verdict.valid) console.log(verdict.reason, verdict.detail);

// 3. Consumption status — the one check that cannot run offline.
const status = await client.getAuthorizationStatus({ authorization: authz });
// status.status === 'burned' means the authorization was already consumed.
```

## The three enforcement strengths

| Strength | Mechanism | Guarantee |
|---|---|---|
| Advisory | `verifyPSBT` (the dry run) | The policy *would* pass now. Nothing is bound; nullifier availability is informational. |
| Software-enforced | **`authorizePSBT`** | A ZK proof binds the authorization to one exact subject; an issuer signature makes the artifact unforgeable and unmodifiable. Enforcement lives in software that reads the artifact. |
| Cryptographically enforced | `signPSBT` | A MuSig2 co-signature makes an unsanctioned transaction invalid *on the Bitcoin network itself*. No enforcer can bypass it. |

**Software-enforced is not equivalent to cosigning.** An authorization is a
signed statement that a policy path was satisfied for one subject; an
enforcer that executes a different transaction than the one it verified has
no on-chain protection. `signPSBT` remains the cryptographically enforced
mode; the two flows share the same stateful allowance (see
[stateful-constraints.md](stateful-constraints.md)) — authorizing and
signing the same action twice is refused by the server with
`AUTHORIZATION_ALREADY_CONSUMED`.

## The artifact

`authorizePSBT` returns an `AuthorizationResult`:

```typescript
{
  artifact: AuthorizationArtifactFields,  // Decoded, re-encode-verified
  rawArtifact: Uint8Array,                // The exact signed encoding
  rawSignature: Uint8Array,               // Issuer Ed25519 over rawArtifact
  envelope: AuthorizationEnvelope,        // The proof bundle backing it
  envelopeJson: string,                   // The issuance wire object
  sessionIdHex: string,
  burnCommitments: [n0Hex, n1Hex],        // Server-echoed burn pair
  actionKeyHex: string,                   // Consumption-status lookup key
  pathId: string,                         // Satisfied policy path
  satisfiedClause: string,
  nullifierStatus: [...],                 // Advisory per-input availability
  policyRoot: string,
}
```

Every result carries the raw artifact bytes and the raw signature. The
signature covers those exact bytes — never a re-encoding — so a verifier can
check it against the artifact as received.

### Wire encoding (version 1)

The artifact is a deterministic little-endian encoding, 281 bytes for the
committed golden vector. Field order is fixed:

| Field | Encoding |
|---|---|
| prefix | 25 bytes, `SIGBASH.AUTHZ.ARTIFACT.V1` |
| version | u16 LE |
| subject_kind, protocol, network | u16-LE length-prefixed UTF-8 |
| subject_commitment, policy_root, scope | 3 × 32 bytes |
| max_uses, issued_at, expires_at | 3 × u64 LE |
| artifact_nonce | 32 bytes |
| issuer_kid, strength | u16-LE length-prefixed UTF-8 |
| burn_set_aggregate | 32 bytes, **always last** |

The burn-set aggregate's trailing position is load-bearing: every byte
before it is independent of its value, so a reader can extract the issuer
key id with a front walk before it has decided anything about the burn
state. Length-prefixed strings are capped at 65,535 bytes; the decoder
refuses truncation, trailing bytes, and unknown versions (`AUTHORIZATION_NON_CANONICAL`,
`AUTHORIZATION_UNKNOWN_VERSION`).

Golden vectors live in `src/contracts/vectors/contracts-v1.json`
(`authorization_artifact_v1`); the Sigbash server encodes artifacts
byte-exactly to these same vectors. The little-endian field order is
canonical for this format — it is a deliberate exception to the big-endian
convention used elsewhere in the server's wire protocol, so do not assume
that convention when reimplementing a decoder.

## Issuing: what `authorizePSBT` does

Gate order, in full — every step before the WASM export is a fail-fast:

1. Client disposed → `ClientDisposedError`.
2. `SigbashWASM_AuthorizePSBT` missing (WASM not loaded) → `WASM_NOT_LOADED`.
3. `lifetimeSeconds` outside `[1, 86400]` → `INVALID_LIFETIME` — before any
   network round trip is spent.
4. `authorize_preflight` socket event (`auth_hash`, `key_id`, `totp_code`,
   `access_generation`). Server gates map to stable codes:
   `TOTP_REQUIRED` / `TOTP_INVALID` / `TOTP_SETUP_INCOMPLETE` /
   `CAPABILITY_NOT_ENABLED`.
5. The preflight echoes the key's registered network; a caller-supplied
   network that disagrees → `NETWORK_MISMATCH`.
6. The WASM export proves the PSBT against the key's policy. Honest
   failures map to stable codes: `POLICY_NOT_SATISFIED` → `POLICY_REJECTED`,
   plus `INVALID_LIFETIME` and `AUTHZ_SESSION_SHAPE_REJECTED`. These are
   expected outcomes, not faults.
7. `authorize_issue` sends the export's commitments and the proof bundle;
   the server re-verifies everything and returns the issuer-signed artifact.
   Issuance over an already-burned action → `AUTHORIZATION_ALREADY_CONSUMED`.
8. Post-decode cross-checks on the returned artifact: canonical decode, the
   issuer signature when the key set is cached, subject commitment / policy
   root agreement with the export, and the burn pair's agreement with the
   envelope. Any disagreement is a hard `SUBJECT_MISMATCH` — the client
   never returns an artifact that disagrees with its own proof.

The flow is tolerant of the idempotent-replay issuance shape (artifact +
signature + `replayed`, no action key): the action key is then derived from
the echoed burn pair.

## Verifying: the offline checklist

`verifyAuthorization` runs nine ordered checks — the order below mirrors the
checklist in `src/authorization/verify.ts`, so a refusal is auditable against
the source. No acceptance path skips any check. Steps 1-5 need only the
artifact, the key set, and the subject; step 6 needs the client salt.

1. **Key set present** — otherwise `ISSUER_UNKNOWN` (step 1). Load it once
   per network with `client.fetchIssuerKeySet(network, sha384Pin)`; the
   bytes are pinned by constant-time SHA-384 compare. A key set loaded
   without a pin carries `pinned: false` — production enforcers always pin.
2. **Canonical decode** — re-encode-and-compare plus the version gate,
   before any acceptance (`AUTHORIZATION_NON_CANONICAL`,
   `AUTHORIZATION_UNKNOWN_VERSION`). Trailing garbage refuses here even
   when the signature bytes are untouched.
3. **Issuer signature** — Ed25519 over the exact received bytes by the
   active key named by `issuerKid` (`ISSUER_UNKNOWN`,
   `AUTHORIZATION_BAD_SIGNATURE`).
4. **Validity window** — the enforcer's clock against `issued_at` /
   `expires_at` (`AUTHORIZATION_NOT_YET_VALID`, `AUTHORIZATION_EXPIRED`).
5. **Protocol and network** — the artifact's claims against the enforcer's
   context (`SUBJECT_MISMATCH`, `NETWORK_MISMATCH`).
6. **Two-stage subject check** (`SUBJECT_MISMATCH`, or
   `SUBJECT_CHECK_UNAVAILABLE` — see below):
   - **Stage 1** re-aggregates the completing bundle's pins from the
     envelope and compares to the signed subject commitment. This binds the
     issuer signature to the envelope.
   - **Stage 2** re-derives the challenge from the RAW subject bytes plus
     the client salt and compares to the envelope's pinned challenge. This
     binds the envelope to the transaction. A verifier that checks only
     stage 1 accepts an envelope minted for a different transaction.
7. **Scope** — the artifact's scope digest against the credential context
   (`SCOPE_MISMATCH`). **Omitting the credential context skips this check
   and weakens verification** — the result detail then says `scope: NOT
   CHECKED`, and an enforcer that cannot check scope must say so in its own
   verdicts. Supply either `credential` (`credentialIdentifier` + key
   index) or `expectedScope`.
8. **Policy-root pin** — `expectedPolicyRoot` when the enforcer pins the
   policy (`POLICY_ROOT_MISMATCH`).
9. **Strength** — the artifact's `strength` against the accepted list,
   which defaults to `['software_enforced']` (`STRENGTH_REJECTED`).

The result is `{ valid: true, detail }` or
`{ valid: false, reason, detail }` — the reason names the first violated
step, and `detail` records the stage and step so a refusal is auditable.

### The salt-secrecy contract

Stage 2's challenge re-derivation uses the client-held policy salt — the
same secret that blinds the nullifiers. The salt never leaves the client;
that is what makes salted nullifiers uncomputable for everyone else, and it
is why offline consumption detection is impossible (use
`getAuthorizationStatus` for that). Consequences:

- `verifyAuthorization` **requires** the salt-bearing context. Without the
  salt (or the raw subject, or the envelope) the subject check cannot run
  and the result is fail-closed `SUBJECT_CHECK_UNAVAILABLE` — there is no
  acceptance path that skips it.
- An external enforcer cannot run stage 2 without the holder's salt. The
  holder runs the full check client-side and can hand over the verdict;
  enforcers without the salt are pinned to stage 1 (envelope authenticity)
  plus their own signature checks.

### What the subject check binds

Every load-bearing field of the transaction moves the challenge: outputs
(values, scripts, order), inputs (outpoints, sequences, prevout amounts),
and the declared sighash posture. Metadata-only PSBT changes — global
key-value pairs such as xpubs — do not move the challenge and still verify.

## Consumption status

Offline verification cannot detect prior consumption: the action key is a
salted digest of the burn nullifiers, and the nullifiers are uncomputable
without key material. `getAuthorizationStatus` asks the server, keyed on
the action key:

```typescript
const { status } = await client.getAuthorizationStatus({
  authorization: authz,        // Or actionKey / burnCommitments directly
});
// 'burned' — consumed by an issuance (this lane or the signing path).
// 'not_found' — unknown to the server. Any unrecognized server response
// maps to 'not_found'; the client never guesses 'burned'.
```

## Key roles: authorization-only vs signing keys

Key summaries carry the container's key-model metadata, visible once the
container is opened:

```typescript
const keys = await client.listKeys();
// Each item gains (optional on KeyListItem, always present on KeySummary):
//   origin: 'sigbash' | 'user_provided'
//   capabilities: KeyCapability[]          // e.g. ['bitcoin_sign', 'transaction_authorize']
//   keyRole: 'signing' | 'authorization_only' | 'signing_and_authorization'
```

`keyRole` is computed from the **capabilities list**, not from origin alone,
so a future sigbash-origin authorize-capable key classifies correctly.
Containers minted before these fields existed deserialize with the legacy
defaults (origin `'sigbash'`, `['bitcoin_sign']`) and therefore display as
signing keys.

This is display and classification metadata only. Origin and capabilities
never enter identity digests, subject commitments, or any other wire
commitment.

### Registering an authorization-only key

`createKey()` accepts an identifier `keyScheme` to mint a key that can only
authorize: the container carries no MuSig2 aggregate material, registers
without the signing-shaped commitment fields, and declares
`capabilities: ['transaction_authorize']` — see
[creating-keys.md § Authorization-only keys](creating-keys.md#authorization-only-keys).

Such a key cannot sign, and the refusal is structural at both ends: the SDK
throws `KEY_NOT_SIGNING_CAPABLE` in `signPSBT()` before any network traffic,
and the server refuses the same key with the same code at signing admission
(both the SDK preflight and the blind-signing path). The authorization lane
is untouched — `authorizePSBT()` works over an authorization-only key exactly
as over any other.

## Error codes

| Code | Meaning |
|---|---|
| `CAPABILITY_NOT_ENABLED` | Transaction authorization is not enabled for the key or organization. |
| `KEY_NOT_SIGNING_CAPABLE` | Signing was attempted on an authorization-only key (an identifier-scheme container). Use `authorizePSBT()`. |
| `TOTP_REQUIRED` / `TOTP_INVALID` / `TOTP_SETUP_INCOMPLETE` | Key requires 2FA; see [admin.md](admin.md). |
| `INVALID_LIFETIME` | `lifetimeSeconds` outside `[1, 86400]` (client, server, or WASM gate). |
| `NETWORK_MISMATCH` | Key's registered network disagrees with the request. |
| `POLICY_REJECTED` | The PSBT does not satisfy the key policy (`POLICY_NOT_SATISFED` from the proof). |
| `AUTHZ_SESSION_SHAPE_REJECTED` | The proof session's shape is outside the authorization lane. |
| `AUTHORIZATION_ALREADY_CONSUMED` | The action's stateful allowance was already spent. |
| `WASM_NOT_LOADED` | `loadWasm()` has not run. |
| `ISSUER_UNKNOWN` | No key set, or the artifact names an unknown issuer key id. |
| `AUTHORIZATION_BAD_SIGNATURE` | Issuer signature does not verify over the received bytes. |
| `AUTHORIZATION_NON_CANONICAL` | The artifact encoding is not canonical (trailing bytes, truncation). |
| `AUTHORIZATION_UNKNOWN_VERSION` | The artifact's version is not supported. |
| `SUBJECT_MISMATCH` | The artifact, envelope, and subject do not all bind. |
| `SUBJECT_CHECK_UNAVAILABLE` | The salt-bearing context is missing — the subject check cannot run (fail-closed). |
| `SCOPE_MISMATCH` / `POLICY_ROOT_MISMATCH` / `STRENGTH_REJECTED` | Verifier-supplied pins disagree. |

## Related

- [authorization.md](authorization.md) — enforcement strengths, verification modes, auditability, and threat boundaries.
- [signing.md](signing.md) — the cryptographically enforced path.
- [verifying.md](verifying.md) — proof-bundle verification for the signing lane.
- [stateful-constraints.md](stateful-constraints.md) — the shared burn allowance.
