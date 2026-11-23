// Test harness only: lets Node's runner resolve the mod's extensionless
// relative imports (`./grant`) to their .ts files, as the Claude Code
// hooks loader does. Usage: node --experimental-strip-types --import ./mod-core-tests/resolve.mjs --test mod-core-tests/core.test.ts
import { register } from 'node:module'

register(
  'data:text/javascript,' +
    encodeURIComponent(`
      export async function resolve(specifier, context, next) {
        if (/^\\.{1,2}\\//.test(specifier) && !/\\.[cm]?[jt]s$/.test(specifier)) {
          try { return await next(specifier + '.ts', context) } catch {}
        }
        return next(specifier, context)
      }`),
  import.meta.url,
)
