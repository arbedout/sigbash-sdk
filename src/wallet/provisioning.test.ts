/**
 * Staged multi-signer wallet provisioning client: the pure-assembly
 * determinism form, the multi-Sigbash pre-flight refusal, and the
 * lifecycle transport's typed rejections.
 */

import { HDKey } from '@scure/bip32';

import { bytesToHex, taggedHash, utf8 } from '../contracts/encoding';
import { SigbashSDKError } from '../errors';
import {
  assembleStagedWalletDescriptor,
  MULTI_SIGBASH_UNSUPPORTED,
  preflightStagedSignerIntent,
  PROVISIONING_INCOMPLETE_COMPILATION,
  PROVISIONING_INVALID_DIGEST,
  stagedSignerCompilations,
  STAGED_EXTERNAL_REQKEY_DIGEST_DOMAIN_TAG,
  StagedProvisioningApi,
  type StagedSignerIntent,
  type StagedSignerSlotHandleV1,
} from './provisioning';
import { walletReqkeyClauseDigest } from './reqkeyTemplate';
import type { WalletSigner } from './walletBuilder';

const SIGNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

function seedXpub(byte: number): string {
  return HDKey.fromMasterSeed(new Uint8Array(32).fill(byte), SIGNET_VERSIONS)
    .publicExtendedKey;
}

function sigbash(byte: number, policyKeyId = 'pk-staged'): WalletSigner {
  return { kind: 'sigbash_policy_key', xpub: seedXpub(byte), policyKeyId };
}

function external(byte: number): WalletSigner {
  return { kind: 'external_xpub', xpub: seedXpub(byte) };
}

function intent(signers: WalletSigner[], sets: number[][] = [[0, 1]]): StagedSignerIntent {
  return { network: 'signet', signers, allowedSignerSets: sets };
}

function slotHandles(...kinds: WalletSigner['kind'][]): StagedSignerSlotHandleV1[] {
  return kinds.map((kind, i) => ({ slot_index: i, kind, slot_token: `tok-${i}` }));
}

describe('multi-Sigbash pre-flight refusal', () => {
  it('refuses an intent with two policy-bound Sigbash signers', () => {
    expect(() => preflightStagedSignerIntent(intent([
      sigbash(0x01, 'pk-a'),
      sigbash(0x02, 'pk-b'),
      external(0x03),
    ], [[0, 1], [0, 2]]))).toThrow();
    try {
      preflightStagedSignerIntent(intent([sigbash(0x01, 'pk-a'), sigbash(0x02, 'pk-b')]));
    } catch (error) {
      expect(error).toBeInstanceOf(SigbashSDKError);
      expect((error as SigbashSDKError).code).toBe(MULTI_SIGBASH_UNSUPPORTED);
    }
  });

  it('accepts one policy-bound Sigbash signer with external roots', () => {
    expect(() => preflightStagedSignerIntent(intent([
      sigbash(0x01),
      external(0x02),
      external(0x03),
    ], [[0, 1], [0, 2]]))).not.toThrow();
  });
});

describe('pure-assembly determinism', () => {
  it('produces the identical digest from identical committed intent', () => {
    const first = assembleStagedWalletDescriptor(intent(
      [sigbash(0x10), external(0x11)],
      [[0, 1]],
    ));
    const second = assembleStagedWalletDescriptor(intent(
      [external(0x11), sigbash(0x10)],
      [[1, 0]],
    ));
    expect(second.descriptorDigest).toBe(first.descriptorDigest);
    expect(first.descriptorDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('keeps the digest stable under origin decoration', () => {
    const plain = assembleStagedWalletDescriptor(intent(
      [sigbash(0x20), external(0x21)],
    ));
    const decorated = assembleStagedWalletDescriptor(intent([
      sigbash(0x20),
      {
        kind: 'external_xpub',
        xpub: seedXpub(0x21),
        origin: {
          masterFingerprint: new Uint8Array([1, 2, 3, 4]),
          path: [84, 0, 0],
        },
      },
    ]));
    expect(decorated.descriptorDigest).toBe(plain.descriptorDigest);
  });

  it('produces a different digest for different committed intent', () => {
    const base = assembleStagedWalletDescriptor(intent(
      [sigbash(0x30), external(0x31)],
    ));
    const otherRoot = assembleStagedWalletDescriptor(intent(
      [sigbash(0x30), external(0x32)],
    ));
    const otherSets = assembleStagedWalletDescriptor(intent(
      [sigbash(0x30), external(0x31), external(0x32)],
      [[0, 1], [0, 2]],
    ));
    expect(otherRoot.descriptorDigest).not.toBe(base.descriptorDigest);
    expect(otherSets.descriptorDigest).not.toBe(base.descriptorDigest);
  });

  it('refuses assembly of a multi-Sigbash intent before building', () => {
    try {
      assembleStagedWalletDescriptor(intent(
        [sigbash(0x01, 'pk-a'), sigbash(0x02, 'pk-b')],
        [[0, 1]],
      ));
      throw new Error('multi-Sigbash assembly must refuse');
    } catch (error) {
      expect((error as SigbashSDKError).code).toBe(MULTI_SIGBASH_UNSUPPORTED);
    }
  });
});

// ---------------------------------------------------------------------------
// Compile producer
// ---------------------------------------------------------------------------

describe('staged compile producer', () => {
  const mixed = intent([sigbash(0x60), external(0x61)]);
  const mixedWallet = assembleStagedWalletDescriptor(mixed).wallet;

  it('derives every record from the assembled wallet', () => {
    const compilation = stagedSignerCompilations(
      mixedWallet,
      slotHandles('sigbash_policy_key', 'external_xpub'),
      { 0: 'b'.repeat(64), 1: 'b'.repeat(64) },
    );
    expect(compilation.perSigner).toHaveLength(2);
    // The Sigbash slot records the digest of the wallet's compiled
    // wallet-ownership REQKEY clause.
    expect(compilation.perSigner[0]).toEqual({
      slot_index: 0,
      policy_root: 'b'.repeat(64),
      reqkey_digest: walletReqkeyClauseDigest(mixedWallet),
    });
    // An external slot carries no wallet-ownership clause: its record is
    // a domain-separated commitment of the signer root it compiled against.
    expect(compilation.perSigner[1]).toEqual({
      slot_index: 1,
      policy_root: 'b'.repeat(64),
      reqkey_digest: bytesToHex(
        taggedHash(STAGED_EXTERNAL_REQKEY_DIGEST_DOMAIN_TAG, utf8(seedXpub(0x61))),
      ),
    });
  });

  it('is deterministic across independent assemblies of the same wallet', () => {
    const first = stagedSignerCompilations(
      mixedWallet,
      slotHandles('sigbash_policy_key', 'external_xpub'),
      { 0: 'b'.repeat(64), 1: 'b'.repeat(64) },
    );
    const second = stagedSignerCompilations(
      assembleStagedWalletDescriptor(mixed).wallet,
      slotHandles('sigbash_policy_key', 'external_xpub'),
      { 0: 'b'.repeat(64), 1: 'b'.repeat(64) },
    );
    expect(second.perSigner).toEqual(first.perSigner);
  });

  it('refuses a slot count that disagrees with the assembled wallet', () => {
    expect(() =>
      stagedSignerCompilations(mixedWallet, slotHandles('sigbash_policy_key'), {
        0: 'b'.repeat(64),
      }),
    ).toThrow(/1 signer slots for a wallet of 2 signers/);
    expect(() =>
      stagedSignerCompilations(
        mixedWallet,
        [
          ...slotHandles('sigbash_policy_key', 'external_xpub'),
          { slot_index: 2, kind: 'external_xpub', slot_token: 'tok-2' },
        ],
        { 0: 'b'.repeat(64), 1: 'b'.repeat(64), 2: 'b'.repeat(64) },
      ),
    ).toThrow(/3 signer slots for a wallet of 2 signers/);
  });

  it('refuses a missing binding token', () => {
    const slots = slotHandles('sigbash_policy_key', 'external_xpub');
    expect(() =>
      stagedSignerCompilations(mixedWallet, [{ ...slots[0], slot_token: '' }, slots[1]], {
        0: 'b'.repeat(64),
        1: 'b'.repeat(64),
      }),
    ).toThrow(/binding token/);
  });

  it('refuses a misaligned slot index', () => {
    expect(() =>
      stagedSignerCompilations(
        mixedWallet,
        slotHandles('sigbash_policy_key', 'external_xpub').map((slot) => ({
          ...slot,
          slot_index: slot.slot_index + 1,
        })),
        { 1: 'b'.repeat(64), 2: 'b'.repeat(64) },
      ),
    ).toThrow(/misaligned/);
  });

  it('refuses a slot kind that disagrees with the assembled wallet', () => {
    expect(() =>
      stagedSignerCompilations(mixedWallet, slotHandles('external_xpub', 'sigbash_policy_key'), {
        0: 'b'.repeat(64),
        1: 'b'.repeat(64),
      }),
    ).toThrow(/disagrees with the assembled wallet/);
  });

  it('refuses a missing or malformed policy root for any slot', () => {
    expect(() =>
      stagedSignerCompilations(mixedWallet, slotHandles('sigbash_policy_key', 'external_xpub'), {
        1: 'b'.repeat(64),
      }),
    ).toThrow(/slot 0/);
    expect(() =>
      stagedSignerCompilations(mixedWallet, slotHandles('sigbash_policy_key', 'external_xpub'), {
        0: 'b'.repeat(64),
        1: 'zz'.repeat(32),
      }),
    ).toThrow(/slot 1/);
  });

  it('surfaces the server refusal codes on every fail-closed path', () => {
    const codes: string[] = [];
    const attempts: Array<() => unknown> = [
      () => stagedSignerCompilations(mixedWallet, [], {}),
      () =>
        stagedSignerCompilations(
          mixedWallet,
          slotHandles('sigbash_policy_key', 'external_xpub').map((slot) => ({
            ...slot,
            slot_index: slot.slot_index + 1,
          })),
          {},
        ),
      () =>
        stagedSignerCompilations(mixedWallet, slotHandles('external_xpub', 'sigbash_policy_key'), {
          0: 'b'.repeat(64),
          1: 'b'.repeat(64),
        }),
      () =>
        stagedSignerCompilations(mixedWallet, slotHandles('sigbash_policy_key', 'external_xpub'), {
          0: 'b'.repeat(64),
        }),
      () =>
        stagedSignerCompilations(mixedWallet, slotHandles('sigbash_policy_key', 'external_xpub'), {
          0: 'b'.repeat(64),
          1: 'zz'.repeat(32),
        }),
    ];
    for (const attempt of attempts) {
      try {
        attempt();
        throw new Error('producer refusal expected');
      } catch (error) {
        codes.push((error as SigbashSDKError).code);
      }
    }
    expect(codes).toEqual([
      PROVISIONING_INCOMPLETE_COMPILATION,
      PROVISIONING_INCOMPLETE_COMPILATION,
      PROVISIONING_INCOMPLETE_COMPILATION,
      PROVISIONING_INVALID_DIGEST,
      PROVISIONING_INVALID_DIGEST,
    ]);
  });
});

// ---------------------------------------------------------------------------
// Cross-implementation golden digest
// ---------------------------------------------------------------------------

// The staged-shaped golden digest is pinned on both sides of the wire: this
// literal is reproduced by the Go staged test section over the identical
// fixture derivation (the signet master xpubs of 32-byte fixed seeds
// 0xD1/0xD2/0xD3, the committed policy-key label 'pk-staged', and the
// mixed two-of-three subsets), so any drift in either side's template
// encoding, tag construction, or digest framing moves it.
const GOLDEN_STAGED_REQKEY_DIGEST = '7d8d483a851a947cdd44a2814046dae30b736b54bce3f479f246bf6ee7a54a36';

describe('staged reqkey clause digest golden', () => {
  it('reproduces the cross-implementation golden digest over the staged fixture', () => {
    const { wallet } = assembleStagedWalletDescriptor({
      network: 'signet',
      signers: [sigbash(0xd1), external(0xd2), external(0xd3)],
      allowedSignerSets: [[0, 1], [0, 2], [0, 1, 2]],
    });
    expect(walletReqkeyClauseDigest(wallet)).toBe(GOLDEN_STAGED_REQKEY_DIGEST);
    // The producer's Sigbash slot record rides the same digest.
    const compilation = stagedSignerCompilations(
      wallet,
      slotHandles('sigbash_policy_key', 'external_xpub', 'external_xpub'),
      { 0: 'b'.repeat(64), 1: 'b'.repeat(64), 2: 'b'.repeat(64) },
    );
    expect(compilation.perSigner[0].reqkey_digest).toBe(GOLDEN_STAGED_REQKEY_DIGEST);
  });
});

// ---------------------------------------------------------------------------
// Lifecycle transport
// ---------------------------------------------------------------------------

type Captured = { path: string; init?: RequestInit };

function transport(responses: Array<{ status: number; body: unknown }>, captured: Captured[]) {
  let call = 0;
  return {
    authedFetch: async (input: string, init?: RequestInit): Promise<Response> => {
      captured.push({ path: input, init });
      const response = responses[Math.min(call, responses.length - 1)];
      call += 1;
      return {
        ok: response.status < 400,
        status: response.status,
        json: async () => response.body,
      } as unknown as Response;
    },
  };
}

const RESERVATION_BASE = '/api/v2/sdk/wallet/provisioning/reservations';

describe('staged provisioning lifecycle transport', () => {
  it('creates a reservation with the canonical body and returns slot tokens', async () => {
    const captured: Captured[] = [];
    const api = new StagedProvisioningApi(transport([
      {
        status: 200,
        body: {
          success: true,
          reservation_id: 'res-1',
          state: 'RESERVED',
          network: 'signet',
          expires_at: '2026-09-28T00:00:00Z',
          slots: [{ slot_index: 0, kind: 'sigbash_policy_key', slot_token: 'tok-0' }],
        },
      },
    ], captured));

    const created = await api.createReservation(intent([sigbash(0x40), external(0x41)]));
    expect(created.reservation_id).toBe('res-1');
    expect(created.slots[0].slot_token).toBe('tok-0');
    expect(captured).toHaveLength(1);
    expect(captured[0].path).toBe(RESERVATION_BASE);
    const body = JSON.parse(String(captured[0].init?.body));
    expect(body.network).toBe('signet');
    expect(body.allowed_signer_sets).toEqual([[0, 1]]);
    // The create body speaks the server's signer contract exactly:
    // {kind, signer_root, policy_key_id?} — no xpub key, no origin.
    expect(body.signers).toEqual([
      { kind: 'sigbash_policy_key', signer_root: seedXpub(0x40), policy_key_id: 'pk-staged' },
      { kind: 'external_xpub', signer_root: seedXpub(0x41) },
    ]);
  });

  it('refuses a multi-Sigbash intent client-side without any request', async () => {
    const captured: Captured[] = [];
    const api = new StagedProvisioningApi(transport([], captured));
    await expect(api.createReservation(intent(
      [sigbash(0x01, 'pk-a'), sigbash(0x02, 'pk-b')],
      [[0, 1]],
    ))).rejects.toMatchObject({ code: MULTI_SIGBASH_UNSUPPORTED });
    expect(captured).toHaveLength(0);
  });

  it('surfaces server rejection codes as typed errors', async () => {
    const captured: Captured[] = [];
    const api = new StagedProvisioningApi(transport([
      { status: 403, body: { error: true, code: MULTI_SIGBASH_UNSUPPORTED, message: 'Seal refused' } },
    ], captured));

    await expect(api.seal('res-1')).rejects.toMatchObject({
      code: MULTI_SIGBASH_UNSUPPORTED,
      message: 'Seal refused',
    });
    expect(captured[0].path).toBe(`${RESERVATION_BASE}/res-1/seal`);
  });

  it('rides the lifecycle paths with the producer-derived records', async () => {
    const captured: Captured[] = [];
    const api = new StagedProvisioningApi(transport([
      {
        status: 200,
        body: {
          success: true,
          reservation_id: 'res-1',
          state: 'RESERVED',
          network: 'signet',
          expires_at: '2026-09-28T00:00:00Z',
          slots: [
            { slot_index: 0, kind: 'sigbash_policy_key', slot_token: 'tok-0' },
            { slot_index: 1, kind: 'external_xpub', slot_token: 'tok-1' },
          ],
        },
      },
      { status: 200, body: { success: true, state: 'ASSEMBLED' } },
      { status: 200, body: { success: true, state: 'COMPILED' } },
      { status: 200, body: { success: true, state: 'SEALED' } },
      { status: 200, body: { success: true, state: 'ACTIVATED' } },
      { status: 200, body: { success: true, state: 'EXPIRED' } },
      { status: 200, body: { success: true, state: 'RESERVED' } },
    ], captured));

    const created = await api.createReservation(intent([sigbash(0x40), external(0x41)]));
    const { wallet } = assembleStagedWalletDescriptor(intent([sigbash(0x40), external(0x41)]));
    await api.assemble('res-1', 'a'.repeat(64));
    await api.compile(
      'res-1',
      stagedSignerCompilations(wallet, created.slots, {
        0: 'b'.repeat(64),
        1: 'b'.repeat(64),
      }),
    );
    await api.seal('res-1');
    await api.activate('res-1');
    await api.abandon('res-1');
    await api.getReservation('res-1');

    expect(captured.map((c) => c.path)).toEqual([
      RESERVATION_BASE,
      `${RESERVATION_BASE}/res-1/assemble`,
      `${RESERVATION_BASE}/res-1/compile`,
      `${RESERVATION_BASE}/res-1/seal`,
      `${RESERVATION_BASE}/res-1/activate`,
      `${RESERVATION_BASE}/res-1`,
      `${RESERVATION_BASE}/res-1`,
    ]);
    const assembleBody = JSON.parse(String(captured[1].init?.body));
    expect(assembleBody.descriptor_digest).toBe('a'.repeat(64));
    const compileBody = JSON.parse(String(captured[2].init?.body));
    expect(compileBody.per_signer).toEqual(
      stagedSignerCompilations(wallet, created.slots, {
        0: 'b'.repeat(64),
        1: 'b'.repeat(64),
      }).perSigner,
    );
    expect(compileBody.per_signer[0].reqkey_digest).toBe(walletReqkeyClauseDigest(wallet));
  });
});
