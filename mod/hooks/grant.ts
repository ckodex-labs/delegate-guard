/**
 * Delegation attenuation: a child grant can never hold more than its parent.
 *
 *   child.tools     ⊆ parent.tools
 *   child.maxCalls  ≤ parent remaining   (reserved from the parent, never copied)
 *   child.expiresAt ≤ parent.expiresAt
 *   child.depth     = parent.depth + 1 ≤ maxDepth
 *   "Agent" ∈ child.tools ⟹ child.depth < maxDepth
 *
 * Pure: no engine, no clock, no I/O. Mirrors crates/grant in the command hook.
 */

export const SPAWN_TOOL = 'Agent'

export type Grant = {
  readonly tools: readonly string[]
  readonly maxCalls: number
  readonly expiresAt: number // epoch ms
  readonly depth: number
}

export type Request = {
  readonly tools: readonly string[]
  readonly maxCalls: number
  readonly ttlMs: number
}

export type Attenuated = { readonly grant: Grant } | { readonly error: string }

export function has(g: Grant, tool: string): boolean {
  return g.tools.includes(tool)
}

export function isExpired(g: Grant, now: number): boolean {
  return now >= g.expiresAt
}

export function intersect(a: readonly string[], b: readonly string[]): string[] {
  const inB = new Set(b)
  return [...new Set(a.filter(x => inB.has(x)))].sort()
}

export function attenuate(
  parent: Grant,
  parentRemaining: number,
  req: Request,
  maxDepth: number,
  now: number,
): Attenuated {
  if (req.tools.length === 0) {
    return { error: 'delegation request lists no tools (deny by default)' }
  }
  if (!(req.maxCalls > 0) || !(req.ttlMs > 0)) {
    return { error: 'requested budget and TTL must be positive' }
  }
  if (isExpired(parent, now)) {
    return { error: 'parent grant has expired' }
  }
  const depth = parent.depth + 1
  if (depth > maxDepth) {
    return { error: `delegation depth limit reached: child depth ${depth} > max ${maxDepth}` }
  }
  if (!(parentRemaining > 0)) {
    return { error: 'parent has no remaining budget to share' }
  }
  let tools = intersect(req.tools, parent.tools)
  if (depth >= maxDepth) {
    tools = tools.filter(t => t !== SPAWN_TOOL) // a leaf may not spawn
  }
  if (tools.length === 0) {
    return { error: "requested tools do not intersect the parent's tools" }
  }
  return {
    grant: {
      tools,
      maxCalls: Math.min(req.maxCalls, parentRemaining),
      expiresAt: Math.min(parent.expiresAt, now + req.ttlMs),
      depth,
    },
  }
}
