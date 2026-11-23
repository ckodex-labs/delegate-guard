// Unit tests of the mod's pure core (grant, policy, ledger), run with Node's
// own runner:  node --experimental-strip-types --import ./mod-core-tests/resolve.mjs --test mod-core-tests/core.test.ts
// The engine-level tests in tests/ need `claude plugin test`.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { attenuate, type Grant, SPAWN_TOOL } from '../mod/hooks/grant'
import { Ledger, MAIN, verify } from '../mod/hooks/ledger'
import { parseDuration, parsePolicy } from '../mod/hooks/policy'

const T0 = Date.UTC(2026, 10, 22, 10)

const POLICY = JSON.stringify({
  root: { tools: ['Agent', 'Bash', 'Glob', 'Grep', 'Read'], max_calls: 30, ttl: '1h' },
  max_depth: 2,
  profiles: {
    Explore: { tools: ['Glob', 'Grep', 'Read', 'Write'], max_calls: 5, ttl: '10m' },
    'general-purpose': { tools: ['Agent', 'Bash', 'Read'], max_calls: 10, ttl: '20m' },
    workflow: { tools: ['Read'], max_calls: 2, ttl: '5m' },
    engine: { tools: ['Read', 'Write'], max_calls: 3, ttl: '5m' },
  },
})

function setup(policy = POLICY) {
  let now = T0
  const ledger = new Ledger(parsePolicy(policy), () => now)
  return { ledger, advance: (ms: number) => (now += ms) }
}

function spawn(ledger: Ledger, parent: string | undefined, type: string, childId: string) {
  const r = ledger.reserve(parent, type, `toolu_${childId}`)
  if ('deny' in r) return r.deny
  ledger.commit(r.reservation, childId)
  return undefined
}

describe('grant.attenuate', () => {
  const root: Grant = { tools: ['Agent', 'Bash', 'Glob', 'Grep', 'Read'], maxCalls: 100, expiresAt: T0 + 3_600_000, depth: 0 }

  test('narrows tools, caps budget and expiry', () => {
    const r = attenuate(root, 7, { tools: ['Read', 'Write', 'Grep'], maxCalls: 50, ttlMs: 86_400_000 }, 2, T0)
    assert.ok('grant' in r)
    assert.deepEqual(r.grant.tools, ['Grep', 'Read'])
    assert.equal(r.grant.maxCalls, 7)
    assert.equal(r.grant.expiresAt, root.expiresAt)
  })

  test('a leaf cannot hold Agent', () => {
    const r = attenuate(root, 10, { tools: ['Agent', 'Read'], maxCalls: 1, ttlMs: 1000 }, 1, T0)
    assert.ok('grant' in r && !r.grant.tools.includes(SPAWN_TOOL))
  })

  test('refusals', () => {
    const cases: Array<[Grant, number, Parameters<typeof attenuate>[2], number, RegExp]> = [
      [root, 10, { tools: [], maxCalls: 1, ttlMs: 1 }, 2, /no tools/],
      [root, 10, { tools: ['Write'], maxCalls: 1, ttlMs: 1 }, 2, /do not intersect/],
      [root, 0, { tools: ['Read'], maxCalls: 1, ttlMs: 1 }, 2, /no remaining budget/],
      [root, 10, { tools: ['Read'], maxCalls: 0, ttlMs: 1 }, 2, /must be positive/],
      [{ ...root, expiresAt: T0 }, 10, { tools: ['Read'], maxCalls: 1, ttlMs: 1 }, 2, /expired/],
      [{ ...root, depth: 2 }, 10, { tools: ['Read'], maxCalls: 1, ttlMs: 1 }, 2, /depth limit/],
    ]
    for (const [p, rem, req, d, re] of cases) {
      const r = attenuate(p, rem, req, d, T0)
      assert.ok('error' in r && re.test(r.error), `${re} vs ${JSON.stringify(r)}`)
    }
  })

  test('never amplifies (200k randomized cases)', () => {
    const universe = ['Agent', 'Bash', 'Edit', 'Glob', 'Grep', 'Read', 'WebFetch', 'Write', 'mcp__x__y']
    // mulberry32: a small PRNG whose low bits are usable (an LCG's alternate).
    let seed = 42
    const rnd = (n: number) => {
      seed = (seed + 0x6d2b79f5) | 0
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
      return (((t ^ (t >>> 14)) >>> 0) % n)
    }
    const pick = () => universe.filter(() => rnd(2) === 0)
    let ok = 0
    for (let i = 0; i < 200_000; i++) {
      const parent: Grant = { tools: pick(), maxCalls: rnd(50), expiresAt: T0 + (rnd(7200) - 600) * 1000, depth: rnd(4) }
      const rem = rnd(parent.maxCalls + 1)
      const maxDepth = rnd(4)
      const r = attenuate(parent, rem, { tools: pick(), maxCalls: rnd(80) - 5, ttlMs: (rnd(10000) - 100) * 1000 }, maxDepth, T0)
      if ('error' in r) continue
      ok++
      const c = r.grant
      assert.ok(c.tools.every(t => parent.tools.includes(t)), `case ${i}: tools`)
      assert.ok(c.maxCalls > 0 && c.maxCalls <= rem, `case ${i}: budget`)
      assert.ok(c.expiresAt <= parent.expiresAt && c.expiresAt > T0, `case ${i}: expiry`)
      assert.ok(c.depth === parent.depth + 1 && c.depth <= maxDepth, `case ${i}: depth`)
      assert.ok(!(c.tools.includes(SPAWN_TOOL) && c.depth >= maxDepth), `case ${i}: leaf spawns`)
    }
    assert.ok(ok > 1000, `only ${ok} successful cases`)
    console.log(`property held on ${ok} successful attenuations out of 200000`)
  })
})

describe('policy', () => {
  test('durations', () => {
    assert.equal(parseDuration('1h30m', 'x'), 5_400_000)
    assert.equal(parseDuration('250ms', 'x'), 250)
    assert.throws(() => parseDuration('10', 'x'))
    assert.throws(() => parseDuration('ten minutes', 'x'))
  })

  test('rejects wildcard, unknown fields, empty tools, bad JSON', () => {
    const base = JSON.parse(POLICY)
    assert.throws(() => parsePolicy(JSON.stringify({ ...base, root: { ...base.root, tools: ['*'] } })), /not allowed/)
    assert.throws(() => parsePolicy(JSON.stringify({ ...base, extra: 1 })), /unknown field "extra"/)
    assert.throws(() => parsePolicy(JSON.stringify({ ...base, root: { ...base.root, tools: [] } })), /non-empty/)
    assert.throws(() => parsePolicy(JSON.stringify({ ...base, root: { ...base.root, max_calls: 0 } })), /positive integer/)
    assert.throws(() => parsePolicy('{nope'), /not valid JSON/)
  })

  test('accepts the command hook policy file as is', () => {
    assert.doesNotThrow(() => parsePolicy(JSON.stringify({ ...JSON.parse(POLICY), pending_ttl: '2m', sidecar_binding: true })))
  })
})

describe('ledger', () => {
  test('main uses only root tools; a child only what both it and its parent hold', () => {
    const { ledger } = setup()
    assert.equal(ledger.check(undefined, 'Read', 't1', false).deny, undefined)
    assert.match(ledger.check(undefined, 'Write', 't2', false).deny ?? '', /"Write" is not in the grant/)
    assert.equal(spawn(ledger, undefined, 'Explore', 'ex-1'), undefined)
    assert.deepEqual(ledger.agent('ex-1')?.grant.tools, ['Glob', 'Grep', 'Read']) // Write dropped
    assert.match(ledger.check('ex-1', 'Write', 't3', true).deny ?? '', /not in the grant/)
    assert.match(ledger.check('ex-1', 'Bash', 't4', true).deny ?? '', /not in the grant/)
  })

  test('budget is reserved from the parent, not copied', () => {
    const { ledger } = setup()
    spawn(ledger, undefined, 'Explore', 'ex-1')
    assert.equal(ledger.agent(MAIN)?.remaining, 25)
    for (let i = 0; i < 5; i++) assert.equal(ledger.check('ex-1', 'Read', `r${i}`, true).deny, undefined)
    assert.match(ledger.check('ex-1', 'Read', 'r5', true).deny ?? '', /exhausted/)
  })

  test('fan-out cannot exceed the parent', () => {
    const { ledger } = setup(JSON.stringify({ ...JSON.parse(POLICY), root: { tools: ['Agent', 'Read'], max_calls: 11, ttl: '1h' } }))
    assert.equal(spawn(ledger, undefined, 'Explore', 'a'), undefined)
    assert.equal(spawn(ledger, undefined, 'Explore', 'b'), undefined)
    assert.equal(spawn(ledger, undefined, 'Explore', 'c'), undefined) // 1 left → child gets 1
    assert.equal(ledger.agent('c')?.grant.maxCalls, 1)
    assert.match(spawn(ledger, undefined, 'Explore', 'd') ?? '', /no remaining budget/)
  })

  test('exact parentage: a grandchild derives from its own parent', () => {
    const { ledger } = setup(JSON.stringify({ ...JSON.parse(POLICY), root: { tools: ['Agent', 'Bash', 'Glob', 'Grep', 'Read'], max_calls: 100, ttl: '1h' } }))
    spawn(ledger, undefined, 'general-purpose', 'gp-1') // [Agent Bash Read]
    assert.equal(spawn(ledger, 'gp-1', 'Explore', 'ex-gp'), undefined)
    assert.equal(spawn(ledger, undefined, 'Explore', 'ex-main'), undefined)
    assert.deepEqual(ledger.agent('ex-gp')?.grant.tools, ['Read']) // gp-1 never held Glob/Grep
    assert.deepEqual(ledger.agent('ex-main')?.grant.tools, ['Glob', 'Grep', 'Read'])
    assert.equal(ledger.agent('ex-gp')?.parent, 'gp-1')
  })

  test('depth: a leaf cannot spawn', () => {
    const { ledger } = setup(JSON.stringify({ ...JSON.parse(POLICY), root: { tools: ['Agent', 'Bash', 'Read'], max_calls: 100, ttl: '1h' } }))
    spawn(ledger, undefined, 'general-purpose', 'gp-1')
    spawn(ledger, 'gp-1', 'general-purpose', 'gp-2')
    assert.ok(!ledger.agent('gp-2')?.grant.tools.includes('Agent'))
    assert.match(spawn(ledger, 'gp-2', 'Explore', 'x') ?? '', /does not hold "Agent"/)
  })

  test('deny by default: unknown type, unadmitted agent, unknown loop without engine profile', () => {
    const { ledger } = setup()
    assert.match(spawn(ledger, undefined, 'Plan', 'p') ?? '', /no delegation profile for "Plan"/)
    assert.match(ledger.check('ghost', 'Read', 'g1', true).deny ?? '', /was not admitted/)
    const noEngine = JSON.parse(POLICY)
    delete noEngine.profiles.engine
    const { ledger: l2 } = setup(JSON.stringify(noEngine))
    assert.match(l2.check('compaction-fork', 'Read', 'c1', false).deny ?? '', /no "engine" profile/)
  })

  test('engine loops get the engine profile, attenuated from main', () => {
    const { ledger } = setup()
    // engine profile asks for Read+Write; main holds no Write, so the loop gets Read only.
    assert.equal(ledger.check('memory-fork', 'Read', 'm1', false).deny, undefined)
    assert.match(ledger.check('memory-fork', 'Write', 'm2', false).deny ?? '', /not in the grant/)
    assert.match(ledger.check('memory-fork', 'Bash', 'm3', false).deny ?? '', /not in the grant/)
    assert.equal(ledger.agent('memory-fork')?.parent, MAIN)
  })

  test('workflow agents use the workflow profile', () => {
    const { ledger } = setup()
    assert.equal(spawn(ledger, undefined, 'workflow', 'wf-a1'), undefined)
    assert.deepEqual(ledger.agent('wf-a1')?.grant.tools, ['Read'])
    ledger.check('wf-a1', 'Read', 'w1', false)
    ledger.check('wf-a1', 'Read', 'w2', false)
    assert.match(ledger.check('wf-a1', 'Read', 'w3', false).deny ?? '', /exhausted/)
  })

  test('expiry, release and resume', () => {
    const { ledger, advance } = setup()
    const r = ledger.reserve(undefined, 'Explore', 'toolu_x')
    assert.ok('reservation' in r)
    ledger.release(r.reservation, 'refused beneath')
    assert.equal(ledger.agent(MAIN)?.remaining, 30) // refunded
    spawn(ledger, undefined, 'Explore', 'ex-1')
    assert.equal(ledger.resume('ex-1').deny, undefined)
    assert.match(ledger.resume('never-seen').deny ?? '', /no grant on record/)
    advance(10 * 60_000)
    assert.match(ledger.check('ex-1', 'Read', 'late', true).deny ?? '', /expired/)
    assert.match(ledger.resume('ex-1').deny ?? '', /expired/)
    assert.equal(ledger.check(undefined, 'Read', 'main-ok', false).deny, undefined)
  })

  test('a re-check of the same call is charged once', () => {
    const { ledger } = setup()
    ledger.check(undefined, 'Read', 'same', false)
    ledger.check(undefined, 'Read', 'same', false)
    assert.equal(ledger.agent(MAIN)?.remaining, 29)
  })

  test('receipts chain and detect tampering', async () => {
    const { ledger } = setup()
    ledger.check(undefined, 'Read', 'a', false)
    spawn(ledger, undefined, 'Explore', 'ex-1')
    ledger.check('ex-1', 'Bash', 'b', true)
    const rs = structuredClone(await ledger.receipts())
    assert.equal(rs.length, 4)
    assert.equal(await verify(rs), undefined)
    const edited = structuredClone(rs)
    edited[3]!.decision = 'pass'
    assert.match((await verify(edited)) ?? '', /hash mismatch/)
    assert.match((await verify([rs[0]!, rs[2]!, rs[3]!])) ?? '', /seq/)
    assert.match((await verify([rs[1]!, rs[0]!])) ?? '', /seq/)
  })
})
