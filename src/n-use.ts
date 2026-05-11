/**
 * Typed helper for COUNT_BASED_CONSTRAINT with arbitrary reset periods.
 *
 * Supports named intervals, duration strings matching /^(\d+)(s|m|h|d|w)$/ (e.g. "6h",
 * "3d", "2w", "90d", "30m"), and raw numeric seconds.  The matching server-side
 * validation enforces floor = 60 s and ceiling = 315_360_000 s (10 years).
 *
 * @example
 * // Vault warm tier: 1 spend per 6 hours
 * import { nUse } from '@sigbash/sdk';
 * const condition = nUse({ maxUses: 1, period: '6h', namespace: 'vault-warm' });
 * // { type: 'COUNT_BASED_CONSTRAINT', max_uses: 1, reset_interval: '6h', counter_namespace: 'vault-warm' }
 */

import type { LeafConditionConfig } from './policy-builder';

/**
 * A reset period accepted by COUNT_BASED_CONSTRAINT.
 *
 * - `"never"` — counter never resets (lifetime cap)
 * - `"daily"` / `"weekly"` / `"monthly"` — calendar shorthands
 * - Duration strings: `"30m"`, `"6h"`, `"3d"`, `"2w"`, `"90d"` (regex `^(\d+)(s|m|h|d|w)$`)
 * - `number` — explicit seconds (0 = never, otherwise [60, 315_360_000])
 */
export type NUsePeriod =
  | 'never'
  | 'hourly'
  | 'daily'
  | 'weekly'
  | 'monthly'
  | `${number}s`
  | `${number}m`
  | `${number}h`
  | `${number}d`
  | `${number}w`
  | number;

export interface NUseOptions {
  /** Maximum signing sessions allowed per reset period. Range: 1–100,000. */
  maxUses: number;
  /**
   * How often the counter resets.  Accepts named intervals, duration strings, or
   * explicit seconds.  See {@link NUsePeriod}.
   */
  period: NUsePeriod;
  /**
   * Optional namespace to isolate this counter from other COUNT_BASED_CONSTRAINT
   * conditions on the same key.  Defaults to "per-constraint" when omitted.
   */
  namespace?: string;
}

/**
 * Build a COUNT_BASED_CONSTRAINT leaf condition with an arbitrary reset period.
 *
 * @example
 * nUse({ maxUses: 1, period: '6h', namespace: 'vault-warm' })
 * nUse({ maxUses: 5, period: 'daily' })
 * nUse({ maxUses: 3, period: 21600 })   // 6 hours as seconds
 * nUse({ maxUses: 1, period: 'never' }) // lifetime cap of 1 use
 */
export function nUse(opts: NUseOptions): LeafConditionConfig {
  const { maxUses, period, namespace } = opts;
  const config: LeafConditionConfig = {
    type: 'COUNT_BASED_CONSTRAINT',
    max_uses: maxUses,
    reset_interval: period,
  };
  if (namespace !== undefined) {
    config.counter_namespace = namespace;
  }
  return config;
}
