import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const source = resolve(process.argv[2]);
const out = resolve(process.argv[3]);
const esm = await import(pathToFileURL(resolve(source, 'libs/langchain/dist/index.js')).href);
const require = createRequire(resolve(source, 'libs/langchain/package.json'));
const cjs = require('./dist/index.cjs');
const { z } = require('zod/v3');
const results = [];
for (const [name, lib, marker] of [['esm/esm', esm, esm], ['cjs/cjs', cjs, cjs], ['esm/cjs', esm, cjs], ['cjs/esm', cjs, esm]]) {
  const error = new Error('local built export probe');
  const agent = lib.createAgent({
    model: new lib.FakeToolCallingModel({ toolCalls: [[{ name: 'boom', args: {}, id: 'call_1' }], []] }),
    tools: [lib.tool(async () => { throw error; }, { name: 'boom', description: 'Local-only tool', schema: z.object({}) })],
    middleware: [lib.createMiddleware({ name: 'Fatal', wrapToolCall: async (request, handler) => {
      try { return await handler(request); } catch (caught) { marker.markToolErrorAsFatal(request, caught); throw caught; }
    } })],
  });
  try { await agent.invoke({ messages: [new lib.HumanMessage('local')] }); results.push({ name, fatal: false }); }
  catch (caught) { results.push({ name, fatal: true, sameError: caught === error }); }
}
writeFileSync(resolve(out, 'built-module-results.json'), `${JSON.stringify(results, null, 2)}\n`);
console.log(JSON.stringify(results));
assert(results.every(result => result.fatal && result.sameError));
