# Creating Keys

## Using a template

```typescript
import { buildPolicyFromTemplate, POLICY_TEMPLATES } from '@sigbash/sdk';

// List available templates:
console.log(Object.keys(POLICY_TEMPLATES));
// → ['weekly-spending-limit', 'treasury-vault', 'bitcoin-inheritance', 'blacklist']

const policy = buildPolicyFromTemplate('weekly-spending-limit', {
  weeklyLimitSats: 500_000,
});

await client.createKey({ policy, network: 'signet', require2FA: false });
```

**Built-in templates:**

| Template ID | Description | Key params |
|---|---|---|
| `weekly-spending-limit` | Max spend per rolling 7-day window | `weeklyLimitSats` |
| `treasury-vault` | IF no admin key THEN restrict amount + destinations | `adminKeyIdentifier`, `hotWalletLimitSats`, `allowedAddresses` |
| `bitcoin-inheritance` | Funds unlock after a timestamp | `unlockTimestamp` |
| `blacklist` | Block specific destination addresses | `blockedAddresses`, `network` |
| `business-hours-only` | Transactions only during Mon–Fri business hours (UTC) | `startHourUTC?` (default `"14:00"`), `endHourUTC?` (default `"22:00"`) |
| `no-new-outputs-consolidation` | All outputs must go to input addresses (UTXO consolidation) | *(none)* |

---

## Using `conditionConfigToPoetPolicy`

```typescript
import { conditionConfigToPoetPolicy } from '@sigbash/sdk';

// AND of two conditions
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 100_000 },
    { type: 'COUNT_BASED_CONSTRAINT', max_uses: 3, reset_interval: 'daily', reset_type: 'rolling' },
  ],
});
```

---

## Using a raw POET policy

```typescript
const policy: POETPolicy = {
  version: '1.1',
  policy: {
    type: 'operator',
    operator: 'AND',
    children: [
      { type: 'condition', conditionType: 'TX_VERSION', conditionParams: { operator: 'EQ', value: 2 } },
      { type: 'condition', conditionType: 'TX_OUTPUT_COUNT', conditionParams: { operator: 'EQ', value: 2 } },
    ],
  },
};
await client.createKey({ policy, network: 'signet', require2FA: false });
```
