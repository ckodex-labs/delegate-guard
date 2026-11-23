// Engine-level tests: run with `claude plugin test mod` (needs the Claude Code
// CLI). `$` is the engine's own, raising each event through the mod as it
// ships; the hooks registered with `on` sit beneath it and stand in for the
// world. Typechecked against the published kit; not yet executed (see README).

import type { Args } from 'claude-code'
import { describe, expect, mock, test, tier } from 'claude-code/testing'

tier('user')

const ENGINE = { plugin: 'engine', tier: 'core' } as const

function spawn(over: Partial<Args<'agent.spawn'>> = {}): Args<'agent.spawn'> {
  return {
    tool_use_id: 'toolu_spawn',
    prompt: 'Read README.md.',
    description: 'read readme',
    subagentType: 'Explore',
    provider: ENGINE,
    parentModel: 'claude-opus-5-5',
    background: false,
    fork: false,
    ...over,
  }
}

function check(tool: string, agentId: string | undefined, id: string): Args<'tool.check'> {
  return { tool, input: {}, tool_use_id: id, ...(agentId === undefined ? {} : { agentId }) }
}

describe('register', () => {
  test('main may spawn an Explore agent; the engine answers beneath', async ($, on) => {
    mock.store(on, {})
    const reached: string[] = []
    on('agent.spawn', ($, e) => {
      reached.push(e.subagentType)
      return { model: 'haiku', agentId: 'child-1' }
    })

    expect(await $.agent.spawn(spawn())).toMatchObject({ agentId: 'child-1' })
    expect(reached).toEqual(['Explore'])
  })

  test('a type with no profile, a teammate and an unadmitted parent are refused before the engine', async ($, on) => {
    mock.store(on, {})
    const reached: string[] = []
    on('agent.spawn', ($, e) => {
      reached.push(e.subagentType)
      return { model: 'haiku', agentId: 'never' }
    })

    const noProfile = await $.agent.spawn(spawn({ subagentType: 'no-such-profile' }))
    // A teammate whose role names a type that has a profile is still a teammate:
    // it gets the reserved "teammate" profile (absent here), not its role's.
    const teammate = await $.agent.spawn(spawn({ subagentType: 'Explore', isTeammate: true, background: true }))
    const orphan = await $.agent.spawn(spawn({ parentAgentId: 'ghost' }))

    expect(noProfile.deny).toContain('no delegation profile for "no-such-profile"')
    expect(teammate.deny).toContain('no delegation profile for "teammate"')
    expect(orphan.deny).toContain('was not admitted')
    expect(reached).toEqual([])
  })

  test("a child's calls are held to its grant; main's are not touched", async ($, on) => {
    mock.store(on, {})
    on('agent.spawn', () => ({ model: 'haiku', agentId: 'child-2' }))
    on('agent.list', () => ({ value: [] }))
    on('tool.check', () => ({ decision: 'ask' }))

    await $.agent.spawn(spawn())

    // The verdict beneath stands where the grant allows: the guard never allows on its own.
    expect(await $.tool.check(check('Read', 'child-2', 't1'))).toMatchObject({ decision: 'ask' })
    expect(await $.tool.check(check('Bash', 'child-2', 't2'))).toMatchObject({
      decision: 'deny',
      reason: expect.stringContaining('"Bash" is not in the grant'),
    })
    expect(await $.tool.check(check('Bash', undefined, 't3'))).toMatchObject({ decision: 'ask' })
  })

  test('a query with no tool_use_id is answered beneath, uncharged', async ($, on) => {
    on('tool.check', () => ({ decision: 'allow' }))

    // WebFetch is outside the root grant: judged as a call it would be denied.
    expect(await $.tool.check({ tool: 'WebFetch', input: {} })).toMatchObject({ decision: 'allow' })
  })

  test('a spawn refused beneath returns its reservation', async ($, on) => {
    let kept: Array<{ decision: string; reason?: string }> = []
    on('store.set', ($, e) => {
      if (e.key === 'receipts') kept = e.value as typeof kept
      return { value: undefined }
    })
    let refuse = true
    on('agent.spawn', () => (refuse ? { deny: 'host said no' } : { model: 'haiku', agentId: 'child-3' }))

    expect((await $.agent.spawn(spawn())).deny).toBe('host said no')
    refuse = false
    expect(await $.agent.spawn(spawn({ tool_use_id: 'toolu_2' }))).toMatchObject({ agentId: 'child-3' })
    expect(kept.map(r => r.decision)).toEqual(['reserve', 'release', 'reserve', 'bind'])
  })

  test('every decision is kept as a hash-chained receipt in the store', async ($, on) => {
    let kept: Array<{ seq: number; decision: string; prev: string; hash: string }> = []
    on('store.set', ($, e) => {
      if (e.key === 'receipts') kept = e.value as typeof kept
      return { value: undefined }
    })
    on('agent.spawn', () => ({ model: 'haiku', agentId: 'child-4' }))
    on('agent.list', () => ({ value: [] }))
    on('tool.check', () => ({ decision: 'ask' }))

    await $.agent.spawn(spawn())
    await $.tool.check(check('Bash', 'child-4', 't9'))

    expect(kept.map(r => r.decision)).toEqual(['reserve', 'bind', 'deny'])
    expect(kept[1]?.prev).toBe(kept[0]?.hash)
    expect(kept[2]?.prev).toBe(kept[1]?.hash)
  })

  test('a store that refuses writes does not change a decision', async ($, on) => {
    on('store.set', () => {
      throw new Error('store full')
    })
    on('agent.spawn', () => ({ model: 'haiku', agentId: 'child-5' }))
    on('agent.list', () => ({ value: [] }))
    on('tool.check', () => ({ decision: 'ask' }))

    expect(await $.agent.spawn(spawn())).toMatchObject({ agentId: 'child-5' })
    expect(await $.tool.check(check('Read', 'child-5', 'u1'))).toMatchObject({ decision: 'ask' })
    expect(await $.tool.check(check('Bash', 'child-5', 'u2'))).toMatchObject({ decision: 'deny' })
  })
})
