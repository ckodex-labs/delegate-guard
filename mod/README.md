# delegate-guard (Claude Code mod)

A Claude Code mod that makes subagent delegation attenuating. Every agent the session starts gets its own grant, derived from the agent that actually spawned it:

- **tools:** a subset of the parent's
- **budget:** reserved out of the parent's pool, not copied
- **expiry:** no later than the parent's

That covers Agent-tool subagents, forks, teammates and workflow `agent()` calls. Every real tool call of every agent loop is then held to its loop's grant. The mod only tightens: it hands back the engine's verdict or a deny, never an allow of its own.

This is the in-engine counterpart of the delegate-guard Rust command hook in the parent folder. A mod reaches two things a command hook cannot:

| Gap for command hooks | How the mod closes it |
| --- | --- |
| No documented link from a subagent to the Agent call that spawned it ([#100198](https://github.com/anthropics/claude-code/issues/100198), [sdk-python#1469](https://github.com/anthropics/claude-agent-sdk-python/issues/1469)) | `agent.spawn` carries `parentAgentId`, and the engine's answer carries the child's `agentId`: binding is exact, no heuristic |
| Workflow-internal `agent()` calls raise no `PreToolUse(Agent)` ([#79953](https://github.com/anthropics/claude-code/issues/79953)) | `agent.spawn` fires for them (`e.workflow`); they use the `workflow` profile, deny by default |
| tmux teammates send no `agent_id` ([#87415](https://github.com/anthropics/claude-code/issues/87415)) | Teammate spawns (`e.isTeammate`) use the `teammate` profile and are refused when it is absent, as in the default policy |

## Hooks

- **`agent.spawn`** (gating, with `.catch` → deny). It resolves the profile key: `workflow`, `fork`, `teammate`, or else the agent type. It attenuates from the exact parent and reserves the budget. On success it binds the child's `agentId`; if the engine refuses or the spawn fails, it releases the reservation. A resume keeps the grant on record, and a resume the guard has no record of is refused.
- **`tool.check`** (gating, with `.catch` → deny). It takes the verdict beneath first. If that is a deny, or the call is a query with no `tool_use_id`, it hands it back unchanged. Otherwise it checks the loop's grant: tool, budget, expiry, closed. An unknown loop that `$.agent.list()` names is denied. One it doesn't name is an engine-internal loop (compaction, memory), which gets the `engine` profile attenuated from main, or is denied if the policy has none.
- **Receipts.** Each decision is a hash-chained receipt kept in memory. The latest 2,000 are written to `$.store` under `receipts`. That write is best-effort: a full or unavailable store never changes a decision.

## Policy

Set the `policy` option (plugin `userConfig`) to the policy as JSON. It's the same shape as the command hook's file, so one file serves both. The default is conservative:

- the main loop holds `Agent Bash Edit Glob Grep Read TodoWrite Write`
- `general-purpose`, `Explore` and `Plan` children get read-only tools
- engine loops get `Edit Glob Grep Read Write`
- no `fork`, `teammate` or `workflow` profile, so all three are refused

The `engine` profile is a first calibration. Verify it against a live session's memory and compaction loops.

## Evidence (Linux amd64, Claude Code 2.1.330)

```
tsc --noEmit (strict, against mods/types/claude-code.d.ts @ 1006c2e)   clean; planted type errors are caught
claude plugin validate mod                                          passed: hooks tool.check, agent.spawn, both gating with .catch
claude plugin test mod                                              7/7 pass, in the engine's own test host
node --test ../mod-core-tests/core.test.ts                          18/18 pass; never-amplifies property held on 52,454 of 200,000 random cases
```

**Mutation check: 14 bugs planted, 14 caught.** Three were caught only after their tests were strengthened, because each first survived:

- teammate falls back to its role's profile
- a refused spawn keeps its reservation
- queries are charged

The other eleven were caught first time: tool.check never denies; the guard approves on its own; `parentAgentId` ignored; a store failure is fatal; budget copied; unadmitted agent allowed; a re-check charged twice; receipts unchained; tools not intersected; budget not capped; a leaf keeps `Agent`.

The engine tests drive the real engine's `$`. The world beneath the mod is stood in for by test hooks, as the kit is designed to do. A live session against a model has **not** been run: `scripts/live-test-mod.sh` in the parent folder does that on an authenticated machine.

## Limitations

1. **Tier.** Installed as a person's (`user`-tier) mod, an organization's `prepend` mods sit above it and have the last word.
2. **Grants name tools, not arguments.**
3. **Budget counts tool calls**, charged once per `tool_use_id`, at check time.
4. **No refund when a child finishes.** A finished subagent can be resumed, so its grant stays open until it expires. This errs toward less authority for the parent.
5. **Receipts in `$.store` are tamper-evident only to whoever cannot rewrite the store.**
6. **Separate-process teammates run their own engine.** This mod has no state there. The default policy refuses teammate spawns for that reason.

## Try it

```sh
claude --plugin-dir mod          # load from source for a session
claude plugin test mod           # the engine-level tests
claude plugin validate mod
```

A LICENSE is still to be chosen. The plugin directory requires one before submission (`claude plugin validate mod --profile directory`).

Not affiliated with or endorsed by Anthropic.
