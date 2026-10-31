import { randomUUID } from 'node:crypto';
import { z } from 'zod';
const EventSchema = z.object({
  stage: z.enum(['startup', 'login', 'sync', 'connection', 'policy', 'update', 'storage', 'lifecycle']),
  code: z.string().regex(/^[A-Z_]{2,64}$/), generation: z.number().int().nonnegative().optional(), durationMs: z.number().min(0).max(3600000).optional(),
}).strict();
export class Diagnostics {
  private events: (z.infer<typeof EventSchema> & { at: string; id: string })[] = [];
  record(input: z.infer<typeof EventSchema>) {
    const event = EventSchema.parse(input); const now = Date.now();
    this.events = this.events.filter(e => now - Date.parse(e.at) < 7 * 86400000).slice(-999);
    this.events.push({ ...event, at: new Date(now).toISOString(), id: randomUUID() });
  }
  export(version: string, platform: string, arch: string) {
    return { schemaVersion: 1, version, platform, arch, createdAt: new Date().toISOString(), contains: ['应用版本', '平台架构', '时间和错误码', '操作耗时'], events: this.events };
  }
}
