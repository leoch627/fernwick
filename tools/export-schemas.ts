import { mkdir, writeFile } from 'node:fs/promises';
import { z } from 'zod';
import { BuildSchema, PolicySchema, AccountSchema } from '../src/shared/schema';
import { ReleaseSchema } from '../src/services/update';
import { RulesSchema } from '../src/domain/compiler';
void (async () => { await mkdir('docs/schemas', { recursive: true }); for (const [name, schema] of Object.entries({ build: BuildSchema, policy: PolicySchema, account: AccountSchema, release: ReleaseSchema, rules: RulesSchema })) await writeFile(`docs/schemas/${name}.schema.json`, JSON.stringify(z.toJSONSchema(schema), null, 2) + '\n'); console.log('Schemas generated from runtime validators. Cross-field refinements additionally run at runtime.'); })();
