# Authorization: enforcement, auditability, and threat boundaries

This page is about what an authorization artifact *means*: who can
enforce it, how strongly, what an auditor can learn from it, and where
its guarantees stop. The API reference — `authorizePSBT`,
`verifyAuthorization`, `getAuthorizationStatus`, wire encoding, error
codes — lives in [transaction-authorization.md](transaction-authorization.md).

One sentence summary: an authorization is a Sigbash-signed statement
that a policy path was satisfied for one exact action, private to the
holder — and it is **not** a Bitcoin signature.

## The three enforcement strengths

Every way of using Sigbash sits at one of three strengths. Keep them
separate in your head and in your copy: they are not the same guarantee.

| Strength | Mechanism | Guarantee |
|---|---|---|
| Advisory | `verifyPSBT` (the dry run) | The policy *would* pass now. Nothing is bound; nullifier availability is informational. |
| Software-enforced | `authorizePSBT` (this lane) | A zero-knowledge proof binds the authorization to one exact subject, and an issuer signature makes the artifact unforgeable and unmodifiable. Enforcement then lives in whatever software reads the artifact. |
| Cryptographically enforced | `signPSBT` | A MuSig2 co-signature makes an unsanctioned transaction invalid *on the Bitcoin network itself*. No enforcer can bypass it. |

**Software-enforced is not equivalent to cosigning.** An enforcer that
receives an artifact and then executes a different transaction has no
on-chain protection — the artifact only gates, it never signs. The
artifact carries `strength: 'software_enforced'` so the distinction is
machine-checkable; documentation and API copy must never present
authorization as equivalent to threshold signing. `signPSBT` remains the
mode of record for value that must not move without Sigbash.

Both lanes share one stateful allowance: authorizing an action burns the
same nullifier commitments signing it would, so no action is ever
approved twice across the two modes. See
[stateful-constraints.md](stateful-constraints.md).

## Verification modes

`verifyAuthorization` runs nine ordered checks (the checklist is in
[transaction-authorization.md](transaction-authorization.md)). They split
by where the evidence lives:

**Offline (no server):** issuer signature against the pinned key set,
canonical encoding, validity window, protocol and network, subject
binding, scope, policy-root pin, strength. These need only the artifact,
the key set, the raw subject — and, for the subject binding, the salt
(see below).

**Server-assisted (one call):** consumption. Offline verification cannot
detect that an action was already used — the action key is a salted
digest of burn nullifiers nobody outside the holder can compute — so
`getAuthorizationStatus` asks the server, keyed on the action key. For
Bitcoin there is also the belt-and-braces check: on-chain consumption of
the inputs is publicly observable.

### The salt boundary, stated plainly

The subject check is two-stage. Stage 1 re-aggregates the proof
envelope's pins and matches them to the signed subject commitment — that
binds the issuer signature to the envelope. Stage 2 re-derives the
blinded challenge from the **raw subject bytes plus the client's policy
salt** and matches it to the envelope's pinned challenge — that binds
the envelope to the transaction. A verifier that runs only stage 1
accepts an envelope minted for a different transaction.

The salt therefore has to be present for full verification, and the salt
never leaves the holder — that is what keeps the nullifiers and the
challenges uncomputable for everyone else. The consequences, honestly:

- In V1 the full check runs **client-side, in the SDK**, where the salt
  already lives. A holder can verify before handing an action to an
  enforcer, and can hand over the verdict.
- A third party holding only the artifact, the issuer key set, and the
  raw PSBT gets fail-closed `SUBJECT_CHECK_UNAVAILABLE`. There is no
  acceptance path that skips the subject check — verification without
  the salt refuses; it never approximates.
- The enforcer snippet below therefore demonstrates the integration
  pattern in the posture V1 supports: the verifying party holds the
  salt-bearing context. Delegating full offline verification to parties
  who hold no client context is a future-version goal, not a V1
  property.

## Enforcer integration pattern

The intended flow: your application receives an action, asks the
Sigbash client for an authorization, receives the artifact, verifies it
independently, and only then executes.

```javascript
// Minimal external-enforcer pattern (Node). The verifying party here
// holds the client's policy salt — the V1 verification posture. A party
// without the salt gets fail-closed SUBJECT_CHECK_UNAVAILABLE, never an
// approximate acceptance.
const { loadWasm } = require('@sigbash/sdk');
await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

// 1. Pin the issuer key set once per network. Compute the SHA-384 of the
//    document out of band and pass it as the pin; an unpinned fetch is a
//    development convenience the result reports as pinned: false.
const keySet = await client.fetchIssuerKeySet('signet', ISSUER_KEYSET_SHA384);

// 2. Before executing the action, verify the artifact against the exact
//    raw PSBT bytes about to be executed — not a copy, the bytes.
const verdict = await client.verifyAuthorization({
  authorization: authz,                    // The artifact from authorizePSBT
  subject: psbtBytes,
  network: 'signet',
  issuerKeySet: keySet,
  salt: policySaltBytes,                   // Client-held policy salt
  credential: { credentialIdentifier: authHashHex, keyIndex: 0 },
  expectedPolicyRoot: policyRootBytes,     // When your enforcer pins the policy
  now: Math.floor(Date.now() / 1000),
});
if (!verdict.valid) throw new Error(`${verdict.reason}: ${JSON.stringify(verdict.detail)}`);

// 3. Consumption is the one check that cannot run offline.
const { status } = await client.getAuthorizationStatus({ authorization: authz });
if (status === 'burned') throw new Error('action already consumed');
// Execute the action here.
```

Failure reasons name the first violated checklist step and the detail
carries the stage, so a refusal is auditable against the source.

## Auditability without privacy loss

The artifact is itself audit evidence. A third party holding an artifact
can verify, offline, that *the Sigbash issuer for this environment
attested, within this validity window, that the action with subject
commitment Y satisfied the policy committed at root X for scope S* —
without learning anything about the action. The commitments are one-way;
the transaction contents, the policy plaintext, and the salts were never
in the artifact or in the issuance traffic.

A holder may later disclose the subject voluntarily — for Bitcoin, the
transaction id — alongside the artifact; the binding makes the
disclosure verifiable rather than merely assertable. Privacy is not
weakened for auditability: nothing in the issuance flow, the server's
records, or the artifact identifies the transaction.

## Threat-model boundaries

What an authorization protects: policy-compliance attestation by Sigbash
over an exact action, privately. What it does not:

- **Execution.** The artifact gates; the enforcer executes. A compromised
  application can bypass software enforcement by definition — only the
  MuSig2 lane is cryptographically enforced.
- **Revocation.** A presented artifact does not self-destruct. V1 has no
  push-revocation channel; consumption is detectable via
  `getAuthorizationStatus` and (for Bitcoin) on-chain observation.
- **Subject coverage for ACP-completing single-input subjects.** A
  session completing on an `SIGHASH_ANYONECANPAY` input binds that
  input's own semantic fields plus the outputs — not the other inputs of
  a multi-input packet, which the ACP posture itself excludes. The
  client's session gate confines this: multi-input sessions must
  complete on a non-ACP position and are refused up front
  (`AUTHZ_SESSION_SHAPE_REJECTED`), so the residual case is a
  single-input ACP subject only.
- **Guarantees stronger than the enforcer's own enforcement.** The
  strength model above is the ceiling.

Two further boundaries worth naming: a compromised issuer key can issue
false attestations — the same failure class as a compromised MuSig2
signer, mitigated by enclave isolation, rotation, and short artifact
lifetimes, but not eliminated; and the server-side consumption lookup is
a small linkability oracle by design — a caller who can present a
subject commitment already knows the shape of the action, and the lookup
discloses only whether that exact action was consumed.

## Related

- [transaction-authorization.md](transaction-authorization.md) — the API surface, wire encoding, and full verify checklist.
- [signing.md](signing.md) — the cryptographically enforced path.
- [verifying.md](verifying.md) — the `verifyPSBT` dry run.
- [stateful-constraints.md](stateful-constraints.md) — the shared burn allowance.
