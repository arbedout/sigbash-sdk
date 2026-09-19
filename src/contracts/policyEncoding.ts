/**
 * Canonical binary serialization for the policy AST (contract 0x07).
 *
 * The canonical form is the binary encoding, not the JSON text: digests and
 * semantic version identity are taken over these bytes. The deterministic
 * whitespace-free JSON rendering (canonicalJson in policyAst.ts) is a view
 * of the same AST for editors and version records, and is round-trip
 * asserted against the binary form.
 *
 * Encoding layout (big-endian, header-first like every contract):
 *
 *   [contract_id u8 = 0x07, version u8 = 1]
 *   node:
 *     kind u8                0x01 operator, 0x02 condition
 *     flags u8               bit0: per-node weight present
 *     [weight u32be]         when bit0 set
 *     operator:
 *       opcode u8            fixed table over the closed POET operator enum
 *       param_flags u8       bit0: k present, bit1: weights present
 *       [k u32be]
 *       [weight_count u16be, weights u32be each]
 *       child_count u16be, children...
 *     condition:
 *       condition_type       length-delimited UTF-8
 *       param_count u16be
 *       per param:           length-delimited UTF-8 key, value tag u8, value
 *
 * Parameter value tags:
 *   0x01 string   length-delimited UTF-8
 *   0x02 boolean  u8
 *   0x03 integer  u64be (non-negative safe integers only)
 *   0x04 other    canonical JSON (sorted keys, whitespace-free) as
 *                 length-delimited UTF-8 — objects, arrays, null, and
 *                 negative or fractional numbers
 *
 * Decoders fail closed on unknown contract ids, unsupported versions,
 * unknown operator codes, and unknown value tags; condition types and
 * parameters are retained verbatim so unknown-but-valid constructs
 * round-trip byte-identically.
 */

import type { OperatorNode, OperatorType, PolicyNode } from '../types';
import {
  bytesToHex,
  concatBytes,
  ContractVersionError,
  Decoder,
  expectExhausted,
  hexToBytes,
  lengthDelimited,
  readContractHeader,
  readLengthDelimited,
  readU16,
  readU32,
  readU64,
  readU8,
  taggedHash,
  u16be,
  u32be,
  u64be,
  u8be,
  utf8,
} from './encoding';
import { canonicalJson, CANONICAL_POLICY_AST_VERSION, type CanonicalPolicyAstV1 } from './policyAst';

export const CANONICAL_POLICY_CONTRACT_ID = 0x07;
export const CANONICAL_POLICY_VERSION = 1;
export const SUPPORTED_CANONICAL_POLICY_VERSIONS = [CANONICAL_POLICY_VERSION] as const;

export const POLICY_AST_DIGEST_TAG = 'SIGBASH/POLICY/V1';
export const POLICY_AST_DIGEST_LENGTH = 32;

const NODE_KIND_OPERATOR = 0x01;
const NODE_KIND_CONDITION = 0x02;

const OPERATOR_CODES: Record<OperatorType, number> = {
  AND: 0x01,
  OR: 0x02,
  NOT: 0x03,
  IMPLIES: 0x04,
  IFF: 0x05,
  THRESHOLD: 0x06,
  WEIGHTED_THRESHOLD: 0x07,
  MAJORITY: 0x08,
  EXACTLY: 0x09,
  AT_MOST: 0x0a,
  VETO: 0x0b,
  NOR: 0x0c,
  NAND: 0x0d,
  XOR: 0x0e,
};

const CODE_TO_OPERATOR: Record<number, OperatorType> = Object.fromEntries(
  Object.entries(OPERATOR_CODES).map(([op, code]) => [code, op as OperatorType]),
);

const VALUE_TAG_STRING = 0x01;
const VALUE_TAG_BOOL = 0x02;
const VALUE_TAG_UINT = 0x03;
const VALUE_TAG_JSON = 0x04;

function encodeNode(node: PolicyNode): Uint8Array[] {
  const weight = (node as { weight?: number }).weight;
  const hasWeight = weight !== undefined;
  const head: Uint8Array[] = [
    u8be(node.type === 'operator' ? NODE_KIND_OPERATOR : NODE_KIND_CONDITION),
    u8be(hasWeight ? 0x01 : 0x00),
  ];
  if (hasWeight) head.push(u32be(weight));

  if (node.type === 'operator') {
    const parts = [...head, u8be(OPERATOR_CODES[node.operator])];
    const k = node.operatorParams?.k;
    const weights = node.operatorParams?.weights;
    parts.push(u8be((k !== undefined ? 0x01 : 0x00) | (weights !== undefined ? 0x02 : 0x00)));
    if (k !== undefined) parts.push(u32be(k));
    if (weights !== undefined) {
      parts.push(u16be(weights.length));
      for (const w of weights) parts.push(u32be(w));
    }
    parts.push(u16be(node.children.length));
    for (const child of node.children) parts.push(...encodeNode(child));
    return parts;
  }

  const parts = [...head, lengthDelimited(utf8(node.conditionType))];
  const keys = Object.keys(node.conditionParams).sort();
  parts.push(u16be(keys.length));
  for (const key of keys) {
    const value = node.conditionParams[key];
    parts.push(lengthDelimited(utf8(key)));
    if (typeof value === 'string') {
      parts.push(u8be(VALUE_TAG_STRING), lengthDelimited(utf8(value)));
    } else if (typeof value === 'boolean') {
      parts.push(u8be(VALUE_TAG_BOOL), u8be(value ? 0x01 : 0x00));
    } else if (
      typeof value === 'number' &&
      Number.isSafeInteger(value) &&
      value >= 0 &&
      value <= 0xffffffffffffffff
    ) {
      parts.push(u8be(VALUE_TAG_UINT), u64be(value));
    } else {
      parts.push(u8be(VALUE_TAG_JSON), lengthDelimited(utf8(canonicalJson(value))));
    }
  }
  return parts;
}

function decodeNode(d: Decoder, path: string): PolicyNode {
  const kind = readU8(d, `${path}.kind`);
  const flags = readU8(d, `${path}.flags`);
  if ((flags & ~0x01) !== 0x00) {
    throw new ContractVersionError(`${path}: unknown node flags 0x${flags.toString(16)}`);
  }
  let weight: number | undefined;
  if ((flags & 0x01) !== 0x00) {
    weight = readU32(d, `${path}.weight`);
  }

  let node: PolicyNode;
  if (kind === NODE_KIND_OPERATOR) {
    const code = readU8(d, `${path}.operator`);
    const operator = CODE_TO_OPERATOR[code];
    if (operator === undefined) {
      throw new ContractVersionError(`${path}: unknown operator code 0x${code.toString(16)}`);
    }
    const paramFlags = readU8(d, `${path}.param_flags`);
    if ((paramFlags & ~0x03) !== 0x00) {
      throw new ContractVersionError(`${path}: unknown operator param flags 0x${paramFlags.toString(16)}`);
    }
    let operatorParams: OperatorNode['operatorParams'];
    if ((paramFlags & 0x01) !== 0x00) {
      operatorParams = { ...(operatorParams ?? {}), k: readU32(d, `${path}.k`) };
    }
    if ((paramFlags & 0x02) !== 0x00) {
      const count = readU16(d, `${path}.weights.count`);
      const weights: number[] = [];
      for (let i = 0; i < count; i++) weights.push(readU32(d, `${path}.weights[${i}]`));
      operatorParams = { ...(operatorParams ?? {}), weights };
    }
    const childCount = readU16(d, `${path}.children.count`);
    if (childCount === 0) {
      throw new Error(`${path}: operator ${operator} requires at least one child`);
    }
    const children: PolicyNode[] = [];
    for (let i = 0; i < childCount; i++) children.push(decodeNode(d, `${path}.children[${i}]`));
    node = { type: 'operator', operator, children, ...(operatorParams !== undefined ? { operatorParams } : {}) };
  } else if (kind === NODE_KIND_CONDITION) {
    const conditionType = new TextDecoder().decode(readLengthDelimited(d, `${path}.condition_type`));
    if (conditionType.length === 0) {
      throw new Error(`${path}: condition type must not be empty`);
    }
    const paramCount = readU16(d, `${path}.params.count`);
    const conditionParams: Record<string, unknown> = {};
    for (let i = 0; i < paramCount; i++) {
      const key = new TextDecoder().decode(readLengthDelimited(d, `${path}.params[${i}].key`));
      const tag = readU8(d, `${path}.params[${i}].tag`);
      let value: unknown;
      if (tag === VALUE_TAG_STRING) {
        value = new TextDecoder().decode(readLengthDelimited(d, `${path}.params[${i}].value`));
      } else if (tag === VALUE_TAG_BOOL) {
        const raw = readU8(d, `${path}.params[${i}].value`);
        if (raw > 0x01) {
          throw new Error(`${path}.params[${i}]: boolean payload must be 0x00 or 0x01`);
        }
        value = raw === 0x01;
      } else if (tag === VALUE_TAG_UINT) {
        const raw = readU64(d, `${path}.params[${i}].value`);
        if (raw > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw new Error(`${path}.params[${i}]: integer exceeds the safe integer range`);
        }
        value = Number(raw);
      } else if (tag === VALUE_TAG_JSON) {
        const json = new TextDecoder().decode(readLengthDelimited(d, `${path}.params[${i}].value`));
        try {
          value = JSON.parse(json);
        } catch {
          throw new Error(`${path}.params[${i}]: JSON value payload is not valid JSON`);
        }
      } else {
        throw new ContractVersionError(`${path}.params[${i}]: unknown value tag 0x${tag.toString(16)}`);
      }
      conditionParams[key] = value;
    }
    node = { type: 'condition', conditionType, conditionParams };
  } else {
    throw new ContractVersionError(`${path}: unknown node kind 0x${kind.toString(16)}`);
  }

  return weight === undefined ? node : ({ ...node, weight } as PolicyNode);
}

function openDecoder(data: Uint8Array): Decoder {
  return { data, offset: 0 };
}

/** Serialize the canonical AST to its canonical binary contract encoding. */
export function encodeCanonicalPolicyAstV1(ast: CanonicalPolicyAstV1): Uint8Array {
  if (ast.version !== CANONICAL_POLICY_AST_VERSION) {
    throw new ContractVersionError(`CanonicalPolicyAst: unsupported version ${ast.version}`);
  }
  return concatBytes(contractHeaderBytes(), ...encodeNode(ast.root));
}

function contractHeaderBytes(): Uint8Array {
  return concatBytes(u8be(CANONICAL_POLICY_CONTRACT_ID), u8be(CANONICAL_POLICY_VERSION));
}

/**
 * Decode the canonical binary encoding. Fails closed on unknown contract
 * ids, unsupported versions, and unknown operator or value codes.
 */
export function decodeCanonicalPolicyAstV1(bytes: Uint8Array): CanonicalPolicyAstV1 {
  const d = openDecoder(bytes);
  readContractHeader(d, CANONICAL_POLICY_CONTRACT_ID, SUPPORTED_CANONICAL_POLICY_VERSIONS, 'CanonicalPolicyAst');
  const root = decodeNode(d, 'n');
  expectExhausted(d, 'CanonicalPolicyAst');
  return { version: CANONICAL_POLICY_AST_VERSION, root };
}

export function canonicalPolicyAstToHex(ast: CanonicalPolicyAstV1): string {
  return bytesToHex(encodeCanonicalPolicyAstV1(ast));
}

export function canonicalPolicyAstFromHex(hex: string): CanonicalPolicyAstV1 {
  return decodeCanonicalPolicyAstV1(hexToBytes(hex));
}

/**
 * Policy AST digest: TaggedHash("SIGBASH/POLICY/V1", canonical binary
 * encoding). This is the digest that fills the user-policy, system-policy,
 * and effective-policy fields of the immutable policy version record.
 */
export function computePolicyAstDigest(ast: CanonicalPolicyAstV1): Uint8Array {
  return taggedHash(POLICY_AST_DIGEST_TAG, encodeCanonicalPolicyAstV1(ast));
}

export function policyAstDigestToHex(digest: Uint8Array): string {
  if (digest.length !== POLICY_AST_DIGEST_LENGTH) {
    throw new Error(`policy AST digest must be ${POLICY_AST_DIGEST_LENGTH} bytes`);
  }
  return bytesToHex(digest);
}

/** Convenience: digest hex directly from a canonical AST. */
export function policyAstDigestHex(ast: CanonicalPolicyAstV1): string {
  return policyAstDigestToHex(computePolicyAstDigest(ast));
}
