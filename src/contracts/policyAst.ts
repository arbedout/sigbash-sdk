/**
 * Canonical policy AST — the application projection over the SDK POET v1.1
 * AST (types.ts POETPolicy/PolicyNode).
 *
 * Layering (architecture decision record, canonical policy AST section):
 *
 *   structured UI  <->  canonical policy AST  <->  canonical POET serialization
 *
 * Every editor, template, diff, and version record operates on this
 * projection — never on form fields and never on raw POET text. This module
 * parses a POET v1.1 JSON document into the canonical projection and applies
 * structural canonicalization only:
 *
 * - nested same-operator AND/OR chains are flattened (n-ary, associative);
 * - children of commutative operators are sorted by their canonical
 *   serialization (the multiset of children is preserved exactly, so
 *   semantics cannot change);
 * - duplicate children (identical canonical serialization, including
 *   weight) are removed only for AND, OR, NAND, and NOR — for the
 *   remaining commutative operators child multiplicity is semantic
 *   (XOR(a,a) is not XOR(a), THRESHOLD(2,[a,a,b]) is not
 *   THRESHOLD(2,[a,b])) and is preserved exactly;
 * - the deprecated top-level `threshold` field is reconciled into
 *   `operatorParams.k`;
 * - cosmetic `description` fields are stripped — they must never affect
 *   canonical bytes or digests.
 *
 * Deliberately NOT done here, with reasons:
 * - no semantic rewriting (no double-NOT collapse, no De Morgan moves,
 *   no threshold algebra) — canonicalization must stay lossless and
 *   provably semantics-preserving by inspection;
 * - no re-implementation of the POET parser or compiler: the WASM parser
 *   (poet_parser.go / poet_validation.go) remains the language authority;
 *   this module validates document structure and the closed operator
 *   enum, and retains every condition type and parameter verbatim so
 *   unknown-but-valid advanced constructs survive without loss.
 */

import type { ConditionNode, OperatorNode, OperatorType, PolicyNode } from '../types';
import { ContractVersionError } from './encoding';

export const CANONICAL_POLICY_AST_VERSION = 1;

/**
 * The closed POET v1.1 operator enum. An operator outside this set is
 * rejected (fail closed) — the AST type has no generic operator node.
 * Unknown CONDITION types and unknown condition parameters are retained
 * verbatim instead; the condition vocabulary is open by design.
 */
const KNOWN_OPERATORS: readonly OperatorType[] = [
  'AND', 'OR', 'NOT', 'IMPLIES', 'IFF',
  'THRESHOLD', 'WEIGHTED_THRESHOLD', 'MAJORITY',
  'EXACTLY', 'AT_MOST', 'VETO', 'NOR', 'NAND', 'XOR',
];

const OPERATOR_SET: ReadonlySet<string> = new Set(KNOWN_OPERATORS);

/** n-ary associative operators whose nested occurrences flatten. */
const ASSOCIATIVE_OPERATORS: ReadonlySet<string> = new Set(['AND', 'OR']);

/** Commutative operators: child order is semantically irrelevant. */
const COMMUTATIVE_OPERATORS: ReadonlySet<string> = new Set([
  'AND', 'OR', 'XOR', 'NAND', 'NOR', 'MAJORITY',
  'THRESHOLD', 'EXACTLY', 'AT_MOST',
]);

/**
 * The commutative operators for which duplicate children carry no extra
 * meaning and are removed. Every other commutative operator treats child
 * multiplicity as semantic — XOR(a,a) is false while XOR(a) is a, and a
 * threshold over [a,a,b] is not a threshold over [a,b] — so their
 * duplicates are preserved and only the order is canonicalized.
 */
const DUPLICATE_INSENSITIVE_OPERATORS: ReadonlySet<string> = new Set([
  'AND', 'OR', 'NAND', 'NOR',
]);

/** Operators taking exactly one child. */
const UNARY_OPERATORS: ReadonlySet<string> = new Set(['NOT', 'VETO']);

/** Canonical projection of a POET v1.1 policy document. */
export interface CanonicalPolicyAstV1 {
  version: typeof CANONICAL_POLICY_AST_VERSION;
  root: PolicyNode;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Deterministic whitespace-free JSON with recursively sorted object keys.
 * The canonical text view of any AST fragment; also the encoding for
 * condition-parameter values that have no dedicated binary tag.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  const ty = typeof value;
  if (ty === 'boolean') return value === true ? 'true' : 'false';
  if (ty === 'number') {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new Error('canonical JSON requires finite numbers');
    }
    if (Object.is(n, -0)) return '0';
    return JSON.stringify(n);
  }
  if (ty === 'string') return JSON.stringify(value as string);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    const parts: string[] = [];
    for (const key of keys) {
      const entry = value[key];
      if (entry === undefined) {
        throw new Error(`canonical JSON requires defined values (key "${key}")`);
      }
      parts.push(`${JSON.stringify(key)}:${canonicalJson(entry)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(`canonical JSON does not support values of type ${ty}`);
}

/** Deterministic sort/dedupe key for a canonical node. */
function nodeSortKey(node: PolicyNode): string {
  const base = canonicalJson(node);
  const weight = (node as { weight?: number }).weight;
  return weight === undefined ? base : `${weight}|${base}`;
}

function assertJsonEncodable(value: unknown, where: string): void {
  if (value === undefined) {
    throw new Error(`${where}: undefined is not a valid parameter value`);
  }
  if (typeof value === 'bigint' || typeof value === 'function' || typeof value === 'symbol') {
    throw new Error(`${where}: values of type ${typeof value} are not valid parameter values`);
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error(`${where}: parameter numbers must be finite`);
  }
  if (Array.isArray(value)) {
    for (const item of value) assertJsonEncodable(item, where);
    return;
  }
  if (isPlainObject(value)) {
    for (const entry of Object.values(value)) assertJsonEncodable(entry, where);
  }
}

function normalizeOperatorParams(node: OperatorNode): OperatorNode {
  const params = node.operatorParams ? { ...node.operatorParams } : undefined;
  if (params?.k !== undefined) {
    if (typeof params.k !== 'number' || !Number.isSafeInteger(params.k) || params.k < 0) {
      throw new Error(`operator ${node.operator}: threshold k must be a non-negative safe integer`);
    }
  }
  if (params?.weights !== undefined) {
    if (
      !Array.isArray(params.weights) ||
      params.weights.some((w) => typeof w !== 'number' || !Number.isSafeInteger(w) || w < 0)
    ) {
      throw new Error(`operator ${node.operator}: weights must be non-negative safe integers`);
    }
  }
  if (params !== undefined) {
    for (const key of Object.keys(params)) {
      if (key !== 'k' && key !== 'weights') {
        throw new Error(`operator ${node.operator}: unsupported operator parameter "${key}"`);
      }
    }
  }
  const deprecatedThreshold = node.threshold;
  if (params?.k !== undefined && deprecatedThreshold !== undefined && params.k !== deprecatedThreshold) {
    throw new Error(
      `operator ${node.operator}: contradictory threshold values (${params.k} vs ${deprecatedThreshold})`,
    );
  }
  if (params?.k === undefined && deprecatedThreshold !== undefined) {
    if (params === undefined) {
      const promoted: OperatorNode = { ...node, operatorParams: { k: deprecatedThreshold } };
      delete promoted.threshold;
      delete promoted.description;
      return promoted;
    }
    params.k = deprecatedThreshold;
  }
  const next: OperatorNode = { ...node };
  if (params !== undefined) {
    next.operatorParams = params;
  } else {
    delete next.operatorParams;
  }
  delete next.threshold;
  delete next.description;
  return next;
}

function canonicalizeNode(input: unknown, path: string): PolicyNode {
  if (!isPlainObject(input)) {
    throw new Error(`${path}: policy node must be an object`);
  }
  const rawType = input['type'];
  if (rawType === 'operator') {
    const operator = input['operator'];
    if (typeof operator !== 'string' || !OPERATOR_SET.has(operator)) {
      throw new ContractVersionError(`${path}: unknown operator "${String(operator)}"`);
    }
    const rawChildren = input['children'];
    if (!Array.isArray(rawChildren) || rawChildren.length === 0) {
      throw new Error(`${path}: operator ${operator} requires at least one child`);
    }
    if (UNARY_OPERATORS.has(operator) && rawChildren.length !== 1) {
      throw new Error(`${path}: operator ${operator} takes exactly one child`);
    }
    let children = rawChildren.map((child, i) => canonicalizeNode(child, `${path}.${i}`));
    if (ASSOCIATIVE_OPERATORS.has(operator)) {
      const flattened: PolicyNode[] = [];
      for (const child of children) {
        if (child.type === 'operator' && child.operator === operator) {
          flattened.push(...child.children);
        } else {
          flattened.push(child);
        }
      }
      children = flattened;
    }
    if (COMMUTATIVE_OPERATORS.has(operator)) {
      children = children
        .map((child, i) => ({ child, key: nodeSortKey(child), i }))
        .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : a.i - b.i))
        .map((entry) => entry.child);
      if (DUPLICATE_INSENSITIVE_OPERATORS.has(operator)) {
        children = children.filter(
          (child, i) => i === 0 || nodeSortKey(child) !== nodeSortKey(children[i - 1]),
        );
      }
    }
    const node: OperatorNode = {
      type: 'operator',
      operator: operator as OperatorType,
      children,
    };
    const withParams = normalizeOperatorParams({
      ...node,
      ...(input['operatorParams'] !== undefined ? { operatorParams: input['operatorParams'] as OperatorNode['operatorParams'] } : {}),
      ...(input['threshold'] !== undefined ? { threshold: input['threshold'] as number } : {}),
      ...(input['weight'] !== undefined ? { weight: input['weight'] as number } : {}),
    } as OperatorNode);
    withParams.children = children;
    if (withParams.weight !== undefined && (!Number.isSafeInteger(withParams.weight) || withParams.weight < 0)) {
      throw new Error(`${path}: node weight must be a non-negative safe integer`);
    }
    return withParams;
  }
  if (rawType === 'condition') {
    const conditionType = input['conditionType'];
    if (typeof conditionType !== 'string' || conditionType.length === 0) {
      throw new Error(`${path}: condition node requires a non-empty conditionType`);
    }
    const rawParams = input['conditionParams'];
    const params: Record<string, unknown> = {};
    if (rawParams !== undefined) {
      if (!isPlainObject(rawParams)) {
        throw new Error(`${path}: conditionParams must be an object`);
      }
      Object.assign(params, rawParams);
    }
    for (const [key, value] of Object.entries(params)) {
      assertJsonEncodable(value, `${path}.conditionParams.${key}`);
    }
    const node: ConditionNode = { type: 'condition', conditionType, conditionParams: params };
    const weight = input['weight'];
    if (weight !== undefined) {
      if (typeof weight !== 'number' || !Number.isSafeInteger(weight) || weight < 0) {
        throw new Error(`${path}: node weight must be a non-negative safe integer`);
      }
      node.weight = weight;
    }
    return node;
  }
  throw new Error(`${path}: unknown node type "${String(rawType)}"`);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const entry of Object.values(value as Record<string, unknown>)) {
      deepFreeze(entry);
    }
    Object.freeze(value);
  }
  return value;
}

/**
 * Canonicalize an already-parsed policy root. Accepts untrusted input and
 * fails closed on unknown operators, malformed structure, and values that
 * have no canonical representation. The result is deeply frozen.
 */
export function canonicalizePolicyRoot(root: unknown): CanonicalPolicyAstV1 {
  return deepFreeze({ version: CANONICAL_POLICY_AST_VERSION, root: canonicalizeNode(root, 'n') });
}

/**
 * Parse a POET v1.1 policy document (JSON text or parsed object) into the
 * canonical projection. Only document version "1.1" is accepted; anything
 * else fails closed.
 */
export function parseCanonicalPolicyAst(input: unknown): CanonicalPolicyAstV1 {
  let doc: unknown = input;
  if (typeof input === 'string') {
    try {
      doc = JSON.parse(input);
    } catch {
      throw new ContractVersionError('POET policy: input is not valid JSON');
    }
  }
  if (!isPlainObject(doc)) {
    throw new Error('POET policy: document must be a JSON object');
  }
  if (doc['version'] !== '1.1') {
    throw new ContractVersionError(`POET policy: unsupported document version "${String(doc['version'])}"`);
  }
  if (doc['policy'] === undefined) {
    throw new Error('POET policy: document requires a policy root');
  }
  return canonicalizePolicyRoot(doc['policy']);
}

/**
 * Stable node identity paths in canonical depth-first order (root "n",
 * children "n.0", "n.1", ...). Because child order is canonical, a node's
 * path is a stable identity for semantic diffing across equivalent
 * policies.
 */
export function policyNodeIdentityPaths(ast: CanonicalPolicyAstV1): string[] {
  const paths: string[] = [];
  const walk = (node: PolicyNode, path: string): void => {
    paths.push(path);
    if (node.type === 'operator') {
      node.children.forEach((child, i) => walk(child, `${path}.${i}`));
    }
  };
  walk(ast.root, 'n');
  return paths;
}
