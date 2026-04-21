/**
 * Policy builder — converts a flexible conditionConfig input shape into a
 * canonical POET v1.1 POETPolicy object.
 *
 * This is the single authoritative implementation shared between the SDK and
 * all E2E test utilities.
 */

import type { POETPolicy, PolicyNode, OperatorNode, OperatorType } from './types';

// ---------------------------------------------------------------------------
// Input type definitions
// ---------------------------------------------------------------------------

export type OperatorAlias = 'THRESH' | 'WTHRESH' | 'EXACT' | 'ATMOST';
export type ConditionConfigOperator = OperatorType | OperatorAlias;

/** Leaf condition: structural keys excluded; 'parameters' sub-object flattened */
export interface LeafConditionConfig {
  type: string;
  weight?: number;
  useNot?: boolean;
  parameters?: Record<string, unknown>;
  [key: string]: unknown;
}

/** Binary operator (left / right) */
export interface BinaryConditionConfig {
  type?: ConditionConfigOperator;
  logic?: ConditionConfigOperator;
  left: ConditionConfig;
  right: ConditionConfig;
  threshold?: number;
  useNot?: boolean;
}

/** Unary NOT */
export interface UnaryConditionConfig {
  type?: 'NOT';
  logic?: 'NOT';
  operand?: ConditionConfig;
  child?: ConditionConfig;
  useNot?: boolean;
}

/** Explicit: { type: 'operator', operator: '...', children: [...] } */
export interface ExplicitOperatorConfig {
  type: 'operator';
  operator: ConditionConfigOperator;
  children?: ConditionConfig[];
  conditions?: ConditionConfig[];
  threshold?: number;
  operatorParams?: { k?: number; threshold?: number; weights?: number[] };
  weights?: number[];
  weight?: number;
  useNot?: boolean;
}

/** Most common: { logic: 'AND', conditions: [...] } */
export interface ConditionsArrayConfig {
  logic: ConditionConfigOperator;
  type?: ConditionConfigOperator;
  conditions?: ConditionConfig[];
  children?: ConditionConfig[];
  threshold?: number;
  operatorParams?: { k?: number; threshold?: number; weights?: number[] };
  weights?: number[];
  useNot?: boolean;
}

export type ConditionConfig =
  | BinaryConditionConfig
  | UnaryConditionConfig
  | ExplicitOperatorConfig
  | ConditionsArrayConfig
  | LeafConditionConfig;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const STRUCTURAL_KEYS = new Set([
  'type', 'logic', 'left', 'right', 'operand', 'child',
  'conditions', 'children', 'searchTerm', 'useNot',
]);

const OPERATOR_MAP: Record<string, OperatorType> = {
  THRESH:  'THRESHOLD',
  WTHRESH: 'WEIGHTED_THRESHOLD',
  EXACT:   'EXACTLY',
  ATMOST:  'AT_MOST',
};

function normaliseOperator(op: string): OperatorType {
  return (OPERATOR_MAP[op] ?? op) as OperatorType;
}

function conditionConfigToPoetNode(config: ConditionConfig): PolicyNode {
  if (!config || typeof config !== 'object') {
    throw new Error(`Invalid conditionConfig node: ${JSON.stringify(config)}`);
  }

  const cfg = config as Record<string, unknown>;

  const isBinaryOperator = cfg['left'] != null && cfg['right'] != null;
  const isUnary =
    (cfg['operand'] != null || cfg['child'] != null) &&
    (cfg['type'] === 'NOT' || cfg['logic'] === 'NOT');
  const isConditionsArray =
    (cfg['logic'] != null || cfg['type'] != null) &&
    Array.isArray(cfg['conditions'] ?? cfg['children']);
  const isExplicitOperatorNode =
    cfg['type'] === 'operator' &&
    cfg['operator'] != null &&
    Array.isArray((cfg['children'] ?? cfg['conditions']));

  if (isBinaryOperator) {
    const children: PolicyNode[] = [
      conditionConfigToPoetNode(cfg['left'] as ConditionConfig),
      conditionConfigToPoetNode(cfg['right'] as ConditionConfig),
    ];
    const op = normaliseOperator((cfg['type'] ?? cfg['logic']) as string);
    const node: PolicyNode = { type: 'operator', operator: op, children };
    if (cfg['threshold'] !== undefined) {
      (node as { operatorParams?: { k: number } }).operatorParams = {
        k: cfg['threshold'] as number,
      };
    }
    return cfg['useNot']
      ? { type: 'operator', operator: 'NOT', children: [node] }
      : node;
  }

  if (isUnary) {
    const inner = conditionConfigToPoetNode(
      (cfg['operand'] ?? cfg['child']) as ConditionConfig
    );
    return { type: 'operator', operator: 'NOT', children: [inner] };
  }

  if (isExplicitOperatorNode || isConditionsArray) {
    const condArray = (
      isExplicitOperatorNode
        ? (cfg['children'] ?? cfg['conditions'])
        : (cfg['conditions'] ?? cfg['children'])
    ) as ConditionConfig[];
    const kids = condArray.map(conditionConfigToPoetNode);
    const rawOp = isExplicitOperatorNode
      ? (cfg['operator'] as string)
      : ((cfg['logic'] ?? cfg['type']) as string);
    const opName = normaliseOperator(rawOp);

    // Build a typed OperatorNode so we can assign operatorParams directly
    const node: OperatorNode = {
      type: 'operator',
      operator: opName,
      children: kids,
    };

    // Threshold: prefer config.threshold, then operatorParams.threshold, then operatorParams.k
    const opParams = cfg['operatorParams'] as
      | { k?: number; threshold?: number; weights?: number[] }
      | undefined;
    const threshVal =
      cfg['threshold'] !== undefined
        ? (cfg['threshold'] as number)
        : opParams?.threshold !== undefined
        ? opParams.threshold
        : opParams?.k;
    if (threshVal !== undefined) {
      node.operatorParams = { ...(node.operatorParams ?? {}), k: threshVal };
    }

    // Weights: top-level array wins; fall back to per-child weight properties.
    // defaultWeight provides the fallback for children without an explicit weight.
    const configWeights = cfg['weights'] as number[] | undefined;
    const defaultWeight = (cfg['defaultWeight'] as number | undefined) ?? 0;
    const weightsVal =
      configWeights !== undefined
        ? configWeights
        : condArray.some(
            (c) => (c as Record<string, unknown>)['weight'] !== undefined
          ) || defaultWeight !== 0
        ? condArray.map(
            (c) => ((c as Record<string, unknown>)['weight'] as number) ?? defaultWeight
          )
        : undefined;
    if (weightsVal !== undefined) {
      node.operatorParams = { ...(node.operatorParams ?? {}), weights: weightsVal };
    }

    return cfg['useNot']
      ? { type: 'operator', operator: 'NOT', children: [node] }
      : node;
  }

  // Leaf condition
  const conditionParams: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(cfg)) {
    if (!STRUCTURAL_KEYS.has(k)) conditionParams[k] = v;
  }
  // Flatten nested 'parameters' sub-object (canonical WASM form is flat)
  if (
    conditionParams['parameters'] != null &&
    typeof conditionParams['parameters'] === 'object'
  ) {
    Object.assign(conditionParams, conditionParams['parameters']);
    delete conditionParams['parameters'];
  }
  const leafNode: PolicyNode = {
    type: 'condition',
    conditionType: cfg['type'] as string,
    conditionParams,
  };
  return cfg['useNot']
    ? { type: 'operator', operator: 'NOT', children: [leafNode] }
    : leafNode;
}

// ---------------------------------------------------------------------------
// Public export
// ---------------------------------------------------------------------------

/**
 * Convert a top-level conditionConfig to a POET v1.1 policy object
 * ready to pass to `client.createKey({ policy })`.
 *
 * A bare condition node (no logic/operator wrapping) is automatically
 * wrapped in an AND operator, mirroring the UI policy builder behaviour.
 */
export function conditionConfigToPoetPolicy(
  conditionConfig: ConditionConfig
): POETPolicy {
  let node = conditionConfigToPoetNode(conditionConfig);
  if (node.type === 'condition') {
    node = { type: 'operator', operator: 'AND', children: [node] };
  }
  return { version: '1.1', policy: node };
}
