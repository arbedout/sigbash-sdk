# Stateful Constraints

If you landed here because `verifyPSBT()` returned `available: false` for an
input, or `signPSBT()` returned `{ success: false }` with a count- or time-related
error, this page explains why. Stateful constraints are the only conditions whose
evaluation depends on prior signing history (counters) or wall-clock time —
everything else is a pure function of the PSBT.

Stateful constraints limit *when* or *how often* a key can sign. They are
enforced server-side — the signing session fails if the constraint is not met.

There are two stateful constraint types:

- **`COUNT_BASED_CONSTRAINT`** — limits the number of signing sessions per time interval
- **`TIME_BASED_CONSTRAINT`** — restricts signing to a wall-clock time window

Both can be combined in the same policy using AND/OR operators.

---

## COUNT_BASED_CONSTRAINT

Rate-limits signing sessions using a server-side counter scoped to this key and
constraint. When `max_uses` is reached, `signPSBT()` returns `{ success: false }`
until the interval resets.

> Counters are per-key — separate keys with the same policy have independent counters.

| Param | Type | Required | Description |
|---|---|---|---|
| `max_uses` | `number` | yes | Maximum signing sessions per interval. Range: `1`–`100,000` (engine cap). |
| `reset_interval` | `string` | yes | `'never'`, `'hourly'`, `'daily'`, `'weekly'`, `'monthly'`, or `'custom'` |
| `reset_interval_seconds` | `number` | only when `reset_interval === 'custom'` | Custom interval length in seconds. Range: `3600` (1 hour) to `31_536_000` (1 year). |
| `reset_type` | `string` | no (default `'rolling'`) | `'rolling'` or `'calendar'` |

**Reset types:**

- `'rolling'` — the interval starts from the first use. E.g. `daily` + `rolling` means
  "5 uses per 24-hour window starting from the first signing."
- `'calendar'` — the interval resets at the calendar boundary, in UTC:
  - `hourly` — top of the hour (`HH:00:00` UTC)
  - `daily` — `00:00` UTC
  - `weekly` — Monday `00:00` UTC
  - `monthly` — day 1 at `00:00` UTC
- `'custom'` — `reset_type` is moot; the boundary is interval-relative (rolling only).

### Examples

```typescript
// Allow 5 signings per rolling 24-hour window
{
  type: 'COUNT_BASED_CONSTRAINT',
  max_uses: 5,
  reset_interval: 'daily',
  reset_type: 'rolling',
}

// One-time use (never resets)
{
  type: 'COUNT_BASED_CONSTRAINT',
  max_uses: 1,
  reset_interval: 'never',
}

// 10 per calendar week (resets Monday 00:00 UTC)
{
  type: 'COUNT_BASED_CONSTRAINT',
  max_uses: 10,
  reset_interval: 'weekly',
  reset_type: 'calendar',
}

// Custom: 4 uses per rolling 6 hours
{
  type: 'COUNT_BASED_CONSTRAINT',
  max_uses: 4,
  reset_interval: 'custom',
  reset_interval_seconds: 21600,
}
```

---

## TIME_BASED_CONSTRAINT

Restricts signing to a wall-clock time window. The mode is selected by the
`constraint_type` field, which takes one of three values:

### `'after'` — unlock after a timestamp

Signing is allowed only **after** the given UNIX timestamp. Use this for
inheritance unlocks or delayed activation.

| Param | Type | Required |
|---|---|---|
| `constraint_type` | `'after'` | yes |
| `start_time` | `number` (UNIX seconds) | yes |

```typescript
// Signing allowed only after Jan 1 2030
{
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'after',
  start_time: 1893456000,
}
```

### `'before'` — expire before a timestamp

Signing is allowed only **before** the given UNIX timestamp. Use this for
expiring keys or time-limited authorizations.

| Param | Type | Required |
|---|---|---|
| `constraint_type` | `'before'` | yes |
| `end_time` | `number` (UNIX seconds) | yes |

```typescript
// Signing expires after Dec 31 2025
{
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'before',
  end_time: 1767225600,
}
```

### `'within'` — recurring time window with day-of-week filter

Signing is allowed only during a specific daily time range on selected days of the
week. `active_days` accepts any subset of days, so you can express weekdays,
Fridays only, weekends, or any custom schedule.

| Param | Type | Required | Description |
|---|---|---|---|
| `constraint_type` | `'within'` | yes | |
| `active_days` | `number[]` | yes | Days of week: 1 = Mon, 2 = Tue, …, 6 = Sat, 7 = Sun |
| `start_hour` | `string` | yes | Start of daily window, `"HH:MM"` UTC |
| `end_hour` | `string` | yes | End of daily window, `"HH:MM"` UTC. **Inclusive** — a session at exactly `end_hour` is allowed. |
| `start_time` | `number` | yes | UNIX timestamp — earliest date the rule is active |
| `end_time` | `number` | yes | UNIX timestamp — latest date the rule is active |
| `start_date_within` | `string` | yes | Human-readable mirror of `start_time` (ISO `"YYYY-MM-DD"` ↔ unix seconds). Provide both; they must agree. |
| `end_date_within` | `string` | yes | Human-readable mirror of `end_time` (ISO `"YYYY-MM-DD"` ↔ unix seconds). Provide both; they must agree. |

```typescript
// Weekdays only, 9 AM–5 PM EST (14:00–22:00 UTC)
{
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'within',
  active_days: [1, 2, 3, 4, 5],   // Mon–Fri
  start_hour: '14:00',
  end_hour: '22:00',
  start_time: 1713571200,
  end_time: 7022323200,
  start_date_within: '2025-04-20',
  end_date_within: '2225-04-20',
}

// Fridays only, any hour
{
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'within',
  active_days: [5],                // Friday only
  start_hour: '00:00',
  end_hour: '23:59',
  start_time: 1713571200,
  end_time: 7022323200,
  start_date_within: '2025-04-20',
  end_date_within: '2225-04-20',
}

// Weekends only
{
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'within',
  active_days: [6, 7],             // Sat + Sun
  start_hour: '00:00',
  end_hour: '23:59',
  start_time: 1713571200,
  end_time: 7022323200,
  start_date_within: '2025-04-20',
  end_date_within: '2225-04-20',
}
```

> **Tip:** The `business-hours-only` template generates `within` boilerplate for
> standard weekday business hours — see [Creating Keys](./creating-keys.md).

### Combining `'after'` + `'before'` for a bounded window

```typescript
import { conditionConfigToPoetPolicy } from '@sigbash/sdk';

// Signing allowed only between Jan 1 2026 and Dec 31 2026
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'TIME_BASED_CONSTRAINT', constraint_type: 'after', start_time: 1735689600 },
    { type: 'TIME_BASED_CONSTRAINT', constraint_type: 'before', end_time: 1767225600 },
  ],
});
```

---

## Combining stateful constraints

Stateful constraints compose with any other condition using standard operators:

```typescript
import { conditionConfigToPoetPolicy } from '@sigbash/sdk';

// Max 50k sats per output, max 3 signings per day, only after Jan 1 2026
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 50_000 },
    { type: 'COUNT_BASED_CONSTRAINT', max_uses: 3, reset_interval: 'daily' },
    { type: 'TIME_BASED_CONSTRAINT', constraint_type: 'after', start_time: 1735689600 },
  ],
});
```

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `verifyPSBT()` returns `available: false` for an input | The key's COUNT counter is exhausted for the current interval, or the current time is outside the TIME window. | Wait for the next reset / time window. See [verifying.md](./verifying.md) for the full availability decision flow. |
| `signPSBT()` returns `{ success: false }` with a count- or time-related error | Same as above — the constraint failed at signing time. | Wait for the next reset / window, or check the policy with [policy-reference.md](./policy-reference.md). |
| Wanted to sign earlier than expected | `reset_interval: 'never'` or `max_uses` set too low for the workload. | Re-author the policy with a larger `max_uses` or a shorter interval (or use `'custom'` with `reset_interval_seconds`). |
| Need to confirm a key would sign before broadcasting | Use [`verifyPSBT()`](./verifying.md) — it evaluates the full policy (including stateful constraints) without consuming a counter slot. |

See also: [signing.md](./signing.md), [policy-reference.md](./policy-reference.md), [verifying.md](./verifying.md).
