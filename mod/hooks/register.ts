import type { On, PluginOptions } from 'claude-code'

import { Ledger } from './ledger'
import { parsePolicy, type Policy } from './policy'

/** The receipts kept in `$.store` (the store holds 4 MiB in all). */
const KEPT_RECEIPTS = 2000

/**
 * Registers delegate-guard.
 *
 * `agent.spawn` (every Agent call, fork, teammate and workflow `agent()`):
 * the child's grant is derived from its exact parent, `e.parentAgentId`, by
 * attenuation, and its budget is reserved from the parent. The engine's answer
 * names the child's `agentId`, so binding is exact: no correlation heuristic.
 *
 * `tool.check` (every real tool call, any loop): the call's loop, `e.agentId`,
 * must hold the tool, budget and time left. The guard only ever tightens: it
 * returns the verdict beneath unchanged or a deny, never an allow of its own.
 *
 * Both fail closed: an invalid policy, or a hook that throws or overruns its
 * budget, refuses.
 *
 * @param on the engine's registrar
 * @param options `policy`: the policy as JSON text (same shape as the command hook's)
 */
export function register(on: On, options: PluginOptions): void {
  let policy: Policy | undefined
  let policyError: string | undefined
  try {
    policy = parsePolicy(String(options.policy ?? ''))
  } catch (error) {
    policyError = error instanceof Error ? error.message : String(error)
  }
  const ledger = policy && new Ledger(policy, () => Date.now())
  const closed = `delegate-guard: ${policyError ?? 'no policy'}; failing closed`

  on('tool.check', async ($, e, next) => {
    const verdict = await next(e)
    // A query ($.tool.check) or a call straight to an MCP server carries no
    // tool_use_id: no loop is spending a call, so nothing is charged.
    if (verdict.decision === 'deny' || e.tool_use_id === undefined) {
      return verdict
    }
    if (ledger === undefined) {
      return { decision: 'deny', reason: closed }
    }
    let isListed = false
    if (e.agentId !== undefined) {
      const agents = await $.agent.list()
      isListed = agents.some(a => a.id === e.agentId)
    }
    const d = ledger.check(e.agentId, e.tool, e.tool_use_id, isListed)
    await persist($, ledger)
    return d.deny === undefined ? verdict : { decision: 'deny', reason: d.deny }
  }).catch(() => ({ decision: 'deny', reason: 'delegate-guard failed; failing closed' }))

  on('agent.spawn', async ($, e, next) => {
    if (ledger === undefined) {
      return { deny: closed }
    }
    if (e.resume !== undefined) {
      const r = ledger.resume(e.resume.agentId)
      await persist($, ledger)
      return r.deny === undefined ? next(e) : { deny: r.deny }
    }
    const key =
      e.workflow !== undefined ? 'workflow'
      : e.fork ? 'fork'
      : e.isTeammate ? 'teammate'
      : e.subagentType
    const r = ledger.reserve(e.parentAgentId, key, e.tool_use_id)
    if ('deny' in r) {
      await persist($, ledger)
      return { deny: r.deny }
    }
    let started
    try {
      started = await next(e)
    } catch (error) {
      ledger.release(r.reservation, `spawn failed: ${String(error)}`)
      throw error
    }
    if (started.deny !== undefined) {
      ledger.release(r.reservation, `refused beneath: ${started.deny}`)
    } else {
      ledger.commit(r.reservation, started.agentId)
    }
    await persist($, ledger)
    return started
  }).catch(($, e, next) => (next.called ? next(e) : { deny: 'delegate-guard failed; failing closed' }))
}

/**
 * Keeps the latest receipts in the plugin's store, so they survive the process.
 *
 * Best-effort by design: a decision never depends on it. A store that is full
 * (4 MiB) or unavailable must not turn bookkeeping into a denial of every call;
 * the receipts stay in memory and the next write tries again.
 */
async function persist(
  $: { store: { set: (key: string, value: unknown) => Promise<void> } },
  ledger: Ledger,
): Promise<void> {
  try {
    const all = await ledger.receipts()
    await $.store.set('receipts', all.slice(-KEPT_RECEIPTS))
  } catch {
    ledger.notePersistFailure()
  }
}
