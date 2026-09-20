/**
 * Xpub import for institutional wallets.
 *
 * A naked xpub is sufficient for onboarding; origin metadata (master
 * fingerprint + full derivation path) may be supplied alongside it and is
 * retained verbatim for PSBT/hardware interoperability. No origin path is
 * ever invented, and key version bytes never override the wallet's explicit
 * network: signet and testnet share tpub-class versions, so the ambiguity
 * resolves from the wallet network, never by guessing.
 */

import { HDKey } from '@scure/bip32';

import { bytesToHex, hexToBytes } from '../contracts/encoding';
import {
  BIP32_HARDENED_KEY_START,
  WALLET_BRANCH_CHANGE,
  WALLET_BRANCH_RECEIVE,
  WALLET_MAX_DERIVATION_INDEX,
  WALLET_NETWORK_PARAMS,
  WALLET_ORIGIN_PATH_MAX_COMPONENTS,
  type WalletNetwork,
} from './constants';
import { WalletXpubError } from './errors';

export interface WalletSignerOrigin {
  /** 4-byte master fingerprint, retained verbatim when supplied. */
  masterFingerprint: Uint8Array;
  /** Full origin path; hardened indices stored as-is (>= 0x80000000). */
  path: number[];
}

export interface ParsedWalletXpub {
  xpub: string;
  origin?: WalletSignerOrigin;
}

interface ParsedExtendedKey {
  hd: HDKey;
  xpub: string;
}

export function parseExtendedPublicKey(network: WalletNetwork, xpub: string, field: string): ParsedExtendedKey {
  const params = WALLET_NETWORK_PARAMS[network];
  let hd: HDKey;
  try {
    hd = HDKey.fromExtendedKey(xpub, {
      private: params.hdPrivateKeyVersion,
      public: params.hdPublicKeyVersion,
    });
  } catch {
    // Version mismatch (including SLIP-132 ypub/zpub/upub/vpub forms and
    // other-network keys), bad checksum, and malformed base58 all fail
    // closed with one static message.
    throw new WalletXpubError(
      `${field} is not a valid public extended key for the ${network} wallet network`
    );
  }
  if (hd.privateKey !== null || hd.publicKey === null) {
    throw new WalletXpubError(`${field} is private; only public extended keys are accepted`);
  }
  return { hd, xpub };
}

/** Derives branch/index from a parsed public key and returns the compressed child key. */
export function deriveWalletChildKey(
  hd: HDKey,
  branch: number,
  index: number
): Uint8Array {
  if (
    branch >= BIP32_HARDENED_KEY_START ||
    index >= BIP32_HARDENED_KEY_START ||
    index > WALLET_MAX_DERIVATION_INDEX
  ) {
    throw new WalletXpubError(
      `derivation path /${branch}/${index} is outside the non-hardened 0..${WALLET_MAX_DERIVATION_INDEX} branch contract`
    );
  }
  const child = hd.derive(`m/${branch}/${index}`);
  if (child.publicKey === null) {
    throw new WalletXpubError(`derivation path /${branch}/${index} produced no public key`);
  }
  return child.publicKey;
}

/**
 * Validates one xpub offered as a wallet signer account derivation root.
 * It must parse as a public extended key with a valid checksum, its version
 * bytes must match the wallet's explicit network, and it must derive valid
 * children for both canonical branches at the first index.
 */
export function validateWalletXpubImport(network: WalletNetwork, xpub: string): void {
  const { hd } = parseExtendedPublicKey(network, xpub, 'extended key');
  for (const branch of [WALLET_BRANCH_RECEIVE, WALLET_BRANCH_CHANGE]) {
    try {
      deriveWalletChildKey(hd, branch, 0);
    } catch {
      throw new WalletXpubError(`extended key cannot derive branch ${branch}`);
    }
  }
}

/**
 * Validates and returns the canonical xpub of an import candidate.
 * Equivalent to validateWalletXpubImport but returns the normalized key for
 * direct use in wallet construction.
 */
export function parseWalletXpubImport(network: WalletNetwork, xpub: string): ParsedWalletXpub {
  parseExtendedPublicKey(network, xpub, 'extended key');
  validateWalletXpubImport(network, xpub);
  return { xpub };
}

/**
 * Validates and retains supplied origin metadata: an 8-hex-character master
 * fingerprint and the full origin path with hardened markers ("h", "H", or
 * "'"). The metadata is retained verbatim; no path is ever invented, and
 * origin data never changes identity semantics. An empty path is valid (the
 * xpub sits directly beneath the master key).
 */
export function parseWalletSignerOrigin(
  masterFingerprintHex: string,
  originPath: string
): WalletSignerOrigin {
  if (masterFingerprintHex.length !== 8) {
    throw new WalletXpubError(
      `master fingerprint must be 8 hex characters, got ${masterFingerprintHex.length}`
    );
  }
  let fingerprint: Uint8Array;
  try {
    fingerprint = hexToBytes(masterFingerprintHex);
  } catch {
    throw new WalletXpubError('master fingerprint is not valid hex');
  }

  const path: number[] = [];
  if (originPath !== '') {
    const parts = originPath.replace(/^m\//, '').split('/');
    if (parts.length > WALLET_ORIGIN_PATH_MAX_COMPONENTS) {
      throw new WalletXpubError(
        `origin path carries ${parts.length} components; at most ${WALLET_ORIGIN_PATH_MAX_COMPONENTS} are allowed`
      );
    }
    for (const part of parts) {
      let body = part;
      let hardened = false;
      if (body.endsWith('h') || body.endsWith('H') || body.endsWith("'")) {
        hardened = true;
        body = body.slice(0, -1);
      }
      if (body === '') {
        throw new WalletXpubError(`origin path component '${part}' is malformed`);
      }
      if (!/^\d+$/.test(body)) {
        throw new WalletXpubError(`origin path component '${part}' is not a valid index`);
      }
      const value = Number(body);
      if (!Number.isSafeInteger(value) || value >= 0x100000000) {
        throw new WalletXpubError(`origin path component '${part}' is not a valid index`);
      }
      if (value >= BIP32_HARDENED_KEY_START) {
        throw new WalletXpubError(
          `origin path component '${part}' already encodes a hardened index; use the plain index with a hardened marker`
        );
      }
      path.push(hardened ? value + BIP32_HARDENED_KEY_START : value);
    }
  }
  return { masterFingerprint: fingerprint, path };
}

/**
 * Resolves the descriptor origin prefix form "[fingerprint/path]xpub" into
 * the origin metadata plus the bare base58 key. Returns null when the input
 * carries no bracketed prefix.
 */
export function splitOriginPrefixedXpub(prefixed: string): { origin?: WalletSignerOrigin; bareXpub: string } | null {
  if (!prefixed.startsWith('[')) {
    return null;
  }
  // The prefix must be exactly "[" + 8 hex fingerprint characters + "]".
  const end = prefixed.indexOf(']');
  if (end !== 9) {
    throw new WalletXpubError('xpub origin prefix is malformed');
  }
  const origin = parseWalletSignerOrigin(prefixed.slice(1, end), '');
  return { origin, bareXpub: prefixed.slice(end + 1) };
}

/** Hex helper for origin fingerprints in tests and logs of public data. */
export function originFingerprintToHex(origin: WalletSignerOrigin): string {
  return bytesToHex(origin.masterFingerprint);
}
