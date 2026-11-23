/**
 * The guard's policy: what the main loop holds, and what each kind of child may
 * ask its parent to delegate. Anything not listed is denied.
 *
 * Profile keys are agent types (`Explore`, `general-purpose`, a plugin's
 * `<plugin>:<name>`), plus four reserved keys for spawns that are not a typed
 * Agent call: `fork`, `teammate`, `workflow`, and `engine` (loops the engine
 * starts by itself, such as compaction or memory, which raise no spawn event).
 * Same JSON shape as the command hook's policy file.
 */

export type Profile = {
  readonly tools: readonly string[]
  readonly maxCalls: number
  readonly ttlMs: number
}

export type Policy = {
  readonly root: Profile
  readonly maxDepth: number
  readonly profiles: Readonly<Record<string, Profile>>
}

const UNIT_MS: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 }

/** Parses Go-style durations: "90s", "10m", "1h30m". */
export function parseDuration(text: unknown, at: string): number {
  if (typeof text !== 'string' || !/^(\d+(ms|s|m|h))+$/.test(text)) {
    throw new Error(`${at}: duration must be a string like "10m" or "1h30m"`)
  }
  let ms = 0
  for (const [, n, unit] of text.matchAll(/(\d+)(ms|s|m|h)/g)) {
    ms += Number(n) * (UNIT_MS[unit as string] ?? NaN)
  }
  return ms
}

function only(obj: unknown, keys: readonly string[], at: string): Record<string, unknown> {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error(`${at}: must be an object`)
  }
  for (const k of Object.keys(obj)) {
    if (!keys.includes(k)) {
      throw new Error(`${at}: unknown field "${k}" (a typo must not widen or drop a constraint)`)
    }
  }
  return obj as Record<string, unknown>
}

function profile(raw: unknown, at: string): Profile {
  const p = only(raw, ['tools', 'max_calls', 'ttl'], at)
  const tools = p.tools
  if (!Array.isArray(tools) || tools.length === 0) {
    throw new Error(`${at}.tools: must be a non-empty list`)
  }
  for (const t of tools) {
    if (typeof t !== 'string' || t === '' || t === '*') {
      throw new Error(`${at}.tools: ${JSON.stringify(t)} not allowed (list tools explicitly)`)
    }
  }
  const maxCalls = p.max_calls
  if (typeof maxCalls !== 'number' || !Number.isInteger(maxCalls) || maxCalls <= 0) {
    throw new Error(`${at}.max_calls: must be a positive integer`)
  }
  const ttlMs = parseDuration(p.ttl, `${at}.ttl`)
  if (ttlMs <= 0) {
    throw new Error(`${at}.ttl: must be positive`)
  }
  return { tools: [...new Set(tools as string[])].sort(), maxCalls, ttlMs }
}

/** Parses and validates a policy given as JSON text. Throws on any problem. */
export function parsePolicy(text: string): Policy {
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch (error) {
    throw new Error(`policy is not valid JSON: ${String(error)}`)
  }
  // pending_ttl and sidecar_binding belong to the command hook; accepted so one file serves both.
  const p = only(raw, ['root', 'max_depth', 'profiles', 'pending_ttl', 'sidecar_binding'], 'policy')
  const maxDepth = p.max_depth
  if (typeof maxDepth !== 'number' || !Number.isInteger(maxDepth) || maxDepth < 0) {
    throw new Error('policy.max_depth: must be an integer >= 0')
  }
  const profilesRaw = only(p.profiles ?? {}, Object.keys((p.profiles ?? {}) as object), 'policy.profiles')
  const profiles: Record<string, Profile> = {}
  for (const [name, pr] of Object.entries(profilesRaw)) {
    profiles[name] = profile(pr, `policy.profiles.${name}`)
  }
  return { root: profile(p.root, 'policy.root'), maxDepth, profiles }
}
