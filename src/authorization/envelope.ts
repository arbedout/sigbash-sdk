/**
 * The authorization lane's proof envelope: the wire object the WASM
 * authorization export returns (AuthorizationEnvelope in
 * wasm/authorization_envelope.go), parsed into typed buffers the verifier
 * and the subject adapter consume.
 *
 * The envelope wraps untouched V3 proof bundles verbatim. Go serializes its
 * fixed-size byte arrays as JSON integer arrays, so every parsed field is
 * length-validated before use — a short or overlong array is a wire error,
 * never a silently truncated buffer.
 *
 * The derived R'_x is deliberately absent from the envelope: R' is a
 * deterministic function of the client salt, so a disclosed value would let
 * any offline envelope holder test salt guesses. The subject adapter
 * re-derives it from the salt it already holds.
 */

export const AUTHORIZATION_ENVELOPE_VERSION = 1;

export type AuthzMuxBranch = 'key_path' | 'tapscript';

/** The canonical encoding shape the circuit used for one position. */
export interface AuthorizationPositionDisclosure {
  /** The EFFECTIVE preimage posture the circuit encoded (the signing fill
   * normalizes non-ACP preimages to SIGHASH_DEFAULT's 0x00 byte; ACP encodes
   * 0x81), not the raw PSBT declaration. */
  hashType: number;
  isAcp: boolean;
  muxBranch: AuthzMuxBranch;
  /** Present only for tapscript positions. */
  leafHash?: Uint8Array;
}

/** The public-input pins the verifier and the pin aggregate consume. */
export interface AuthorizationPublicInputs {
  /** BlindedChallengeE — e' + beta (mod 2^256), carry discarded. */
  challengeE: Uint8Array;
  pathId: Uint8Array;
  sessionSeed: Uint8Array;
  nullifierN0: Uint8Array;
  nullifierN1: Uint8Array;
  hashOutputsBlindedCommit: Uint8Array;
  hashOutputsBlindedCommitUnified: Uint8Array;
  hinBlindedCommitUnified: Uint8Array;
  saltBlindedCommitUnified: Uint8Array;
  polyCoeffsBlindedCommitUnified: Uint8Array;
  inputSetPolyProduct: Uint8Array;
  /** 0 = SIGNED, 1 = COORDINATION. */
  positionMode: number;
}

/** One output-chunk link's session-level pins. */
export interface AuthorizationChunkPins {
  isFinalChunk: boolean;
  covenantWriteCommit: Uint8Array;
}

/** One position's verbatim V3 bundle, pared to the fields the lane consumes. */
export interface AuthorizationBundle {
  publicInputs: AuthorizationPublicInputs;
  proofSessionId: Uint8Array;
  outputChunkProofs: AuthorizationChunkPins[];
}

export interface AuthorizationEnvelopePosition {
  bundle: AuthorizationBundle;
  posture: AuthorizationPositionDisclosure;
  positionMode: number;
}

export interface AuthorizationEnvelope {
  version: number;
  sessionId: Uint8Array;
  completingPosition: number;
  positions: AuthorizationEnvelopePosition[];
}

export class AuthorizationEnvelopeFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthorizationEnvelopeFormatError';
    Object.setPrototypeOf(this, AuthorizationEnvelopeFormatError.prototype);
  }
}

function fail(message: string): never {
  throw new AuthorizationEnvelopeFormatError(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** Parse a Go-fixed-size byte array field (JSON integer array) to a buffer. */
export function fixedBytes(value: unknown, length: number, field: string): Uint8Array {
  if (!Array.isArray(value) || value.length !== length ||
      value.some(b => !Number.isInteger(b) || b < 0 || b > 0xff)) {
    fail(`${field} must be a ${length}-byte array`);
  }
  return Uint8Array.from(value as number[]);
}

function optionalFixedBytes(
  record: Record<string, unknown>, key: string, length: number, field: string,
): Uint8Array | undefined {
  if (record[key] === undefined) return undefined;
  return fixedBytes(record[key], length, field);
}

function parseDisclosure(value: unknown): AuthorizationPositionDisclosure {
  if (!isRecord(value)) fail('position posture must be an object');
  const hashType = value.hash_type;
  if (typeof hashType !== 'number' || !Number.isInteger(hashType)) {
    fail('posture hash_type must be an integer');
  }
  const muxBranch = value.mux_branch;
  if (muxBranch !== 'key_path' && muxBranch !== 'tapscript') {
    fail(`posture mux_branch must be 'key_path' or 'tapscript', got ${String(muxBranch)}`);
  }
  const leafHash = optionalFixedBytes(value, 'leaf_hash', 32, 'posture.leaf_hash');
  return {
    hashType,
    isAcp: value.is_acp === true,
    muxBranch,
    leafHash,
  };
}

function parsePublicInputs(value: unknown): AuthorizationPublicInputs {
  if (!isRecord(value)) fail('bundle public_inputs must be an object');
  const mode = value.position_mode;
  if (typeof mode !== 'number' || !Number.isInteger(mode) || mode < 0 || mode > 0xff) {
    fail('public input position_mode must be a byte-sized integer');
  }
  return {
    challengeE: fixedBytes(value.challenge_e, 32, 'public_inputs.challenge_e'),
    pathId: fixedBytes(value.path_id, 32, 'public_inputs.path_id'),
    sessionSeed: fixedBytes(value.session_seed, 32, 'public_inputs.session_seed'),
    nullifierN0: fixedBytes(value.nullifier_n0, 32, 'public_inputs.nullifier_n0'),
    nullifierN1: fixedBytes(value.nullifier_n1, 32, 'public_inputs.nullifier_n1'),
    hashOutputsBlindedCommit: fixedBytes(
      value.hash_outputs_blinded_commit, 32, 'public_inputs.hash_outputs_blinded_commit'),
    hashOutputsBlindedCommitUnified: fixedBytes(
      value.hash_outputs_blinded_commit_unified, 32,
      'public_inputs.hash_outputs_blinded_commit_unified'),
    hinBlindedCommitUnified: fixedBytes(
      value.hin_blinded_commit_unified, 32, 'public_inputs.hin_blinded_commit_unified'),
    saltBlindedCommitUnified: fixedBytes(
      value.salt_blinded_commit_unified, 32, 'public_inputs.salt_blinded_commit_unified'),
    polyCoeffsBlindedCommitUnified: fixedBytes(
      value.poly_coeffs_blinded_commit_unified, 32,
      'public_inputs.poly_coeffs_blinded_commit_unified'),
    inputSetPolyProduct: fixedBytes(
      value.input_set_poly_product, 16, 'public_inputs.input_set_poly_product'),
    positionMode: mode,
  };
}

function parseChunkProof(value: unknown): AuthorizationChunkPins {
  if (!isRecord(value)) fail('output chunk proof must be an object');
  return {
    isFinalChunk: value.is_final_chunk === true,
    covenantWriteCommit: fixedBytes(
      value.covenant_write_commit, 16, 'chunk.covenant_write_commit'),
  };
}

function parseBundle(value: unknown): AuthorizationBundle {
  if (!isRecord(value)) fail('position bundle must be an object');
  const chunks = value.output_chunk_proofs;
  return {
    publicInputs: parsePublicInputs(value.public_inputs),
    proofSessionId: fixedBytes(value.proof_session_id, 32, 'bundle.proof_session_id'),
    outputChunkProofs: chunks === undefined ? [] : (
      Array.isArray(chunks) ? chunks.map(parseChunkProof) : fail('output_chunk_proofs must be an array')
    ),
  };
}

/**
 * Parse the authorization envelope the WASM export returns as JSON.
 * Structural checks only — the cryptographic verification happens in the
 * verifier; this parser guarantees only that every consumed field exists at
 * its declared width.
 */
export function parseAuthorizationEnvelope(input: string | Record<string, unknown>): AuthorizationEnvelope {
  const record = typeof input === 'string'
    ? (isRecord(JSON.parse(input)) ? JSON.parse(input) : fail('envelope must be a JSON object'))
    : input;
  const version = record.version;
  if (version !== AUTHORIZATION_ENVELOPE_VERSION) {
    fail(`unsupported authorization envelope version ${String(version)}`);
  }
  const completingPosition = record.completing_position;
  if (typeof completingPosition !== 'number' || !Number.isInteger(completingPosition)) {
    fail('completing_position must be an integer');
  }
  const rawPositions = record.positions;
  if (!Array.isArray(rawPositions) || rawPositions.length === 0) {
    fail('envelope must carry at least one position');
  }
  if (completingPosition < 0 || completingPosition >= rawPositions.length) {
    fail('completing_position is out of range for the position list');
  }
  const positions = rawPositions.map((raw) => {
    if (!isRecord(raw)) fail('position must be an object');
    const bundle = parseBundle(raw.bundle);
    const posture = parseDisclosure(raw.posture);
    const positionMode = raw.position_mode;
    if (typeof positionMode !== 'number' || !Number.isInteger(positionMode) ||
        positionMode < 0 || positionMode > 0xff) {
      fail('position_mode must be a byte-sized integer');
    }
    return { bundle, posture, positionMode };
  });
  return {
    version: AUTHORIZATION_ENVELOPE_VERSION,
    sessionId: fixedBytes(record.session_id, 32, 'session_id'),
    completingPosition,
    positions,
  };
}

/**
 * The canonical covenant write commit for one bundle: the FIRST chunk
 * marked is_final_chunk, else the LAST chunk's value, else zero — the same
 * selection the WASM export and the Sigbash server's verifier apply before aggregating.
 */
export function selectCovenantWriteCommit(bundle: AuthorizationBundle): Uint8Array {
  const chunks = bundle.outputChunkProofs;
  const selected =
    chunks.find(c => c.isFinalChunk) ??
    (chunks.length > 0 ? chunks[chunks.length - 1] : undefined);
  return selected ? selected.covenantWriteCommit : new Uint8Array(16);
}

/** The position whose proof carries the chain-completing pins. */
export function completingPositionOf(envelope: AuthorizationEnvelope): AuthorizationEnvelopePosition {
  return envelope.positions[envelope.completingPosition];
}
