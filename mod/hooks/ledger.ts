/**
 * The guard's state for one session: every agent loop's grant, the spawns in
 * flight, and a hash-chained receipt for every decision.
 *
 * Pure except for `crypto.subtle` (a web API the hooks runtime provides): the
 * clock is injected and nothing here touches the engine, so the same code runs
 * under the engine and under plain unit tests.
 */

import { type Grant, attenuate, has, isExpired, SPAWN_TOOL } from './grant'
import type { Policy } from './policy'

export const MAIN = 'main'

export type AgentState = {
  grant: Grant
  remaining: number
  parent?: string
  type: string
  closed?: boolean
}

export type Reservation = {
  readonly id: number
  readonly parent: string
  readonly type: string
  readonly toolUseId: string
  readonly grant: Grant
}

export type Receipt = {
  seq: number
  time: number
  event: string
  actor: string
  type?: string
  tool?: string
  toolUseId?: string
  decision: 'pass' | 'deny' | 'reserve' | 'bind' | 'release' | 'resume'
  reason?: string
  prev: string
  hash: string
}

export const GENESIS = '0'.repeat(64)

export type Verdict = { readonly deny?: string }

export class Ledger {
  readonly #policy: Policy
  readonly #now: () => number
  readonly #agents = new Map<string, AgentState>()
  readonly #reserved = new Map<number, Reservation>()
  readonly #charged = new Set<string>()
  readonly #receipts: Receipt[] = []
  #chain: Promise<string> = Promise.resolve(GENESIS)
  #nextId = 1

  constructor(policy: Policy, now: () => number) {
    this.#policy = policy
    this.#now = now
  }

  /** The main loop's state, created on first use with the root grant. */
  #main(): AgentState {
    let m = this.#agents.get(MAIN)
    if (m === undefined) {
      const r = this.#policy.root
      m = {
        grant: { tools: r.tools, maxCalls: r.maxCalls, expiresAt: this.#now() + r.ttlMs, depth: 0 },
        remaining: r.maxCalls,
        type: MAIN,
      }
      this.#agents.set(MAIN, m)
    }
    return m
  }

  #actor(agentId: string | undefined): [string, AgentState | undefined] {
    if (agentId === undefined || agentId === '') {
      return [MAIN, this.#main()]
    }
    this.#main()
    return [agentId, this.#agents.get(agentId)]
  }

  /**
   * Decides one tool call of a loop. `isListed` says whether `$.agent.list()`
   * names the loop: an unknown loop that is listed is a real agent the guard did
   * not admit (denied); one that is not is an engine-internal loop, which gets
   * the `engine` profile if the policy has one, and is denied otherwise.
   */
  check(agentId: string | undefined, tool: string, toolUseId: string | undefined, isListed: boolean): Verdict {
    if (toolUseId !== undefined && this.#charged.has(toolUseId)) {
      return {} // the same call decided twice (a re-check) is charged once
    }
    const now = this.#now()
    let [actor, a] = this.#actor(agentId)
    if (a === undefined && !isListed && this.#policy.profiles.engine !== undefined) {
      a = this.#adoptEngineLoop(actor, now)
    }
    let deny: string | undefined
    if (a === undefined) {
      deny = isListed
        ? `agent ${actor} was not admitted by delegate-guard; denying ${tool}`
        : `loop ${actor} is unknown and the policy has no "engine" profile; denying ${tool}`
    } else if (a.closed) {
      deny = `agent ${actor}'s grant is closed`
    } else if (isExpired(a.grant, now)) {
      deny = `grant for ${actor} expired at ${new Date(a.grant.expiresAt).toISOString()}`
    } else if (!has(a.grant, tool)) {
      deny = `tool "${tool}" is not in the grant for ${actor} [${a.grant.tools.join(' ')}]`
    } else if (a.remaining <= 0) {
      deny = `budget for ${actor} exhausted (${a.grant.maxCalls} calls)`
    }
    if (deny !== undefined) {
      this.#record({ event: 'tool.check', actor, tool, toolUseId, decision: 'deny', reason: deny })
      return { deny: `delegate-guard: ${deny}` }
    }
    a!.remaining -= 1
    if (toolUseId !== undefined) this.#charged.add(toolUseId)
    this.#record({ event: 'tool.check', actor, tool, toolUseId, decision: 'pass', reason: `remaining=${a!.remaining}` })
    return {}
  }

  #adoptEngineLoop(actor: string, now: number): AgentState | undefined {
    const main = this.#main()
    const p = this.#policy.profiles.engine!
    const r = attenuate(main.grant, main.remaining, { tools: p.tools, maxCalls: p.maxCalls, ttlMs: p.ttlMs }, Number.MAX_SAFE_INTEGER, now)
    if ('error' in r) return undefined
    main.remaining -= r.grant.maxCalls
    const a: AgentState = { grant: r.grant, remaining: r.grant.maxCalls, parent: MAIN, type: 'engine' }
    this.#agents.set(actor, a)
    this.#record({ event: 'engine-loop', actor, type: 'engine', decision: 'bind', reason: `engine profile; tools=[${r.grant.tools.join(' ')}] budget=${r.grant.maxCalls}` })
    return a
  }

  /**
   * Admits a spawn under `parentAgentId` (absent = main) and reserves the
   * child's budget from the parent. The caller must `commit` or `release` it.
   */
  reserve(parentAgentId: string | undefined, typeKey: string, toolUseId: string): { reservation: Reservation } | { deny: string } {
    const now = this.#now()
    const [parent, p] = this.#actor(parentAgentId)
    const fail = (reason: string) => {
      this.#record({ event: 'agent.spawn', actor: parent, type: typeKey, toolUseId, decision: 'deny', reason })
      return { deny: `delegate-guard: ${reason}` }
    }
    if (p === undefined) return fail(`spawner ${parent} was not admitted`)
    if (p.closed) return fail(`spawner ${parent}'s grant is closed`)
    if (!has(p.grant, SPAWN_TOOL)) return fail(`spawner ${parent} does not hold "${SPAWN_TOOL}"`)
    const prof = this.#policy.profiles[typeKey]
    if (prof === undefined) return fail(`no delegation profile for "${typeKey}" (deny by default)`)
    const r = attenuate(p.grant, p.remaining, { tools: prof.tools, maxCalls: prof.maxCalls, ttlMs: prof.ttlMs }, this.#policy.maxDepth, now)
    if ('error' in r) return fail(`cannot delegate to "${typeKey}": ${r.error}`)
    p.remaining -= r.grant.maxCalls
    const reservation: Reservation = { id: this.#nextId++, parent, type: typeKey, toolUseId, grant: r.grant }
    this.#reserved.set(reservation.id, reservation)
    this.#record({ event: 'agent.spawn', actor: parent, type: typeKey, toolUseId, decision: 'reserve', reason: `tools=[${r.grant.tools.join(' ')}] budget=${r.grant.maxCalls}; parent remaining=${p.remaining}` })
    return { reservation }
  }

  /** Binds the started child to its reservation: exact, by the engine's own agentId. */
  commit(res: Reservation, agentId: string | undefined): void {
    if (!this.#reserved.delete(res.id)) return
    if (agentId === undefined || agentId === '') {
      // A remote workflow agent has no local loop; its budget stays spent.
      this.#record({ event: 'agent.spawn', actor: res.parent, type: res.type, toolUseId: res.toolUseId, decision: 'bind', reason: 'started with no local agentId (remote); reservation kept' })
      return
    }
    this.#agents.set(agentId, { grant: res.grant, remaining: res.grant.maxCalls, parent: res.parent, type: res.type })
    this.#record({ event: 'agent.spawn', actor: agentId, type: res.type, toolUseId: res.toolUseId, decision: 'bind', reason: `child of ${res.parent}` })
  }

  /** Returns a reservation's budget to its parent (the spawn was refused or failed). */
  release(res: Reservation, why: string): void {
    if (!this.#reserved.delete(res.id)) return
    const p = this.#agents.get(res.parent)
    if (p !== undefined && !p.closed) p.remaining += res.grant.maxCalls
    this.#record({ event: 'agent.spawn', actor: res.parent, type: res.type, toolUseId: res.toolUseId, decision: 'release', reason: why })
  }

  /** A resumed agent keeps the grant it had; one the guard never admitted is refused. */
  resume(agentId: string): Verdict {
    const a = this.#agents.get(agentId)
    const deny =
      a === undefined ? `cannot resume ${agentId}: no grant on record in this session`
      : a.closed ? `cannot resume ${agentId}: its grant is closed`
      : isExpired(a.grant, this.#now()) ? `cannot resume ${agentId}: its grant has expired`
      : undefined
    this.#record({ event: 'agent.spawn', actor: agentId, type: a?.type, decision: deny ? 'deny' : 'resume', reason: deny })
    return deny ? { deny: `delegate-guard: ${deny}` } : {}
  }

  #persistFailures = 0

  /** Counts receipt writes the store refused; shown by `persistFailures`. */
  notePersistFailure(): void {
    this.#persistFailures += 1
  }

  get persistFailures(): number {
    return this.#persistFailures
  }

  agent(id: string): Readonly<AgentState> | undefined {
    return this.#agents.get(id)
  }

  /** The receipts written so far, with every hash computed. */
  async receipts(): Promise<readonly Receipt[]> {
    await this.#chain
    return this.#receipts
  }

  #record(r: Omit<Receipt, 'seq' | 'time' | 'prev' | 'hash'>): void {
    const rec: Receipt = { seq: this.#receipts.length + 1, time: this.#now(), ...r, prev: '', hash: '' }
    this.#receipts.push(rec)
    this.#chain = this.#chain.then(async prev => {
      rec.prev = prev
      rec.hash = await digest(rec)
      return rec.hash
    })
  }
}

/** sha256 over the record's canonical body, which includes `prev`. */
export async function digest(r: Receipt): Promise<string> {
  const { hash: _omit, ...body } = r
  const canon = JSON.stringify(body, Object.keys(body).sort())
  const sum = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canon))
  return [...new Uint8Array(sum)].map(b => b.toString(16).padStart(2, '0')).join('')
}

/** Checks a receipt chain: sequence, links and hashes. Returns the first fault. */
export async function verify(receipts: readonly Receipt[]): Promise<string | undefined> {
  let prev = GENESIS
  for (const [i, r] of receipts.entries()) {
    if (r.seq !== i + 1) return `receipt ${i + 1}: seq ${r.seq}`
    if (r.prev !== prev) return `receipt ${r.seq}: prev does not match`
    if (r.hash !== (await digest(r))) return `receipt ${r.seq}: hash mismatch (altered)`
    prev = r.hash
  }
  return undefined
}
