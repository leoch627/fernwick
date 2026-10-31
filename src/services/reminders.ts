import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { Account } from '../shared/schema';
export const ReminderStateSchema = z.object({ schemaVersion: z.literal(1), events: z.array(z.object({ key: z.string().regex(/^[a-f0-9]{64}$/), thresholdDays: z.number().int().min(0).max(30), expiresAt: z.number().safe() }).strict()).max(256) }).strict();
export type ReminderState = z.infer<typeof ReminderStateSchema>;
/** No email or account ID is written to the public notification ledger. */
export class ExpiryReminders {
  private state: ReminderState = { schemaVersion: 1, events: [] }; private running: Promise<void> = Promise.resolve();
  constructor(private tenant: string, private save: (value: ReminderState) => Promise<void>, private notify: (remainingMs: number) => Promise<void>) {}
  restore(value: unknown) { this.state = ReminderStateSchema.parse(value); }
  check(account: Account, thresholds: readonly number[], now: number, current = () => true) {
    const operation = this.running.then(async () => {
      if (!current() || account.sessionStatus !== 'valid' || account.hasPlan !== 'yes' || account.expiryKind !== 'finite' || !account.expiresAt || account.banned === 'yes') return;
      const expiry = Date.parse(account.expiresAt), remaining = expiry - now;
      const threshold = remaining <= 0 ? 0 : [...new Set(thresholds)].filter(days => days >= 1 && days <= 30 && remaining <= days * 86400000).sort((a, b) => a - b)[0];
      if (threshold === undefined) return;
      const key = createHash('sha256').update(JSON.stringify([this.tenant, account.accountId, expiry])).digest('hex');
      const prior = this.state.events.find(event => event.key === key); if (prior && prior.thresholdDays <= threshold) return;
      const next: ReminderState = { schemaVersion: 1, events: [...this.state.events.filter(event => event.key !== key && event.expiresAt > now - 30 * 86400000), { key, thresholdDays: threshold, expiresAt: expiry }].slice(-256) };
      // Reserve before sending so polling, restart and concurrent ticks cannot generate duplicate prompts.
      await this.save(next); this.state = next; if (current()) await this.notify(remaining);
    }); this.running = operation.catch(() => {}); return operation;
  }
}
