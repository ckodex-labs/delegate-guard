#!/usr/bin/env bash
# Summarizes one scripts/upstream-repro.sh run directory as JSON on stdout.
# Reads only files that scripts/upstream-scrub.sh also publishes (run.json,
# hooks.jsonl, the stream, sidecars/), so scripts/upstream-verify.sh can
# recompute every verdict from the public copy.
set -euo pipefail
out="$1"
stream="$out/stream.jsonl"; [ -f "$stream" ] || stream="$out/stream.tool-calls.jsonl"
# Subagent tool calls as the transcripts record them, independent of hooks.
subdir="$out/subagent-tool-calls"; [ -d "$subdir" ] || subdir="$out/transcripts/session/subagents"
subcalls="$(if [ -d "$subdir" ]; then find "$subdir" -name '*.jsonl' -exec cat {} +; fi | jq -sc '[.[] | ((.message.content // .content) // [])[]? | select(type == "object" and (.type == "tool_use" or .type == "tool_result"))]')"
sidecars="$(if [ -d "$out/sidecars" ]; then find "$out/sidecars" -name '*.meta.json' | sort | while IFS= read -r f; do
  jq -c --arg f "${f#"$out/sidecars/"}" '{file: $f, content: .}' "$f"; done; fi | jq -sc .)"

jq -n --slurpfile run "$out/run.json" --slurpfile h "$out/hooks.jsonl" --slurpfile s "$stream" --argjson sc "$sidecars" --argjson sub "$subcalls" '
  $run[0] as $r
  | [$h[] | .p + {_t: .t, _sc: .sidecar_at_hook, _where: (if .p.agent_id then "subagent" else "main" end)}] as $ev
  | ([$s[] | select(.type=="system" and .subtype=="init")] | first) as $init
  | [$s[] | select(.type=="result")] as $results
  | ([$ev[] | select(.hook_event_name=="PreToolUse") | {key: .tool_use_id, value: (.agent_id // "main")}] | from_entries) as $owner
  | ([$ev[] | select(.hook_event_name=="PostToolUse" and (.tool_name=="Agent" or .tool_name=="Task")) | {key: .tool_use_id, value: (.tool_response.agentId? // null)}] | from_entries) as $spawned
  | def n(f): [$ev[] | select(f)] | length;
    def probe_ok: (.tool_input.command == $r.probe_command) and ((.tool_response | tostring) | contains($r.expected_output));
    def sc(e): {agent_type: e.agent_type, exists: (e._sc.exists // false), toolUseId: (e._sc.toolUseId != null), parentAgentId: (e._sc.parentAgentId != null)};
  {
    experiment: $r.experiment, claude_code: $r.claude_code, os_version: $r.os_version, kernel: $r.kernel,
    model: $init.model, permission_mode: $r.permission_mode, hook_mode: $r.hook_mode, exit_status: $r.exit_status,
    main_tools_include: {Bash: ($init.tools | index("Bash") != null), Agent: (($init.tools | index("Agent")) != null or ($init.tools | index("Task")) != null), Write: ($init.tools | index("Write") != null)},
    plugins: [$init.plugins[]? | if type == "object" then .source else . end],
    hooks_run: ([$s[] | select(.type=="system" and .subtype=="hook_started") | .hook_name] | group_by(.) | map({name: .[0], n: length})),
    agent_calls: [$ev[] | select(.hook_event_name=="PreToolUse" and (.tool_name=="Agent" or .tool_name=="Task" or .tool_name=="Workflow"))
      | {where: ._where, tool: .tool_name, subagent_type: .tool_input.subagent_type, run_in_background: .tool_input.run_in_background}],
    subagent_starts: [$ev[] | select(.hook_event_name=="SubagentStart") | .agent_type],
    sidecar_at_subagent_start: [$ev[] | select(.hook_event_name=="SubagentStart") | sc(.)],
    sidecar_at_first_tool: ($ev | map(select(.hook_event_name=="PreToolUse" and .agent_id)) | group_by(.agent_id) | map(sort_by(._t) | .[0] | sc(.))),
    sidecars_final: [$sc[] | .content as $c | {file, spawnDepth: $c.spawnDepth, agentType: $c.agentType, inWorkflowRun: ($c.inWorkflowRun // false),
      toolUseId: (if $c.toolUseId == null then "absent"
        elif ($spawned[$c.toolUseId] // null) == null then "no Agent result with that tool_use_id"
        elif ("agent-" + $spawned[$c.toolUseId] + ".meta.json") == (.file | split("/") | last) then "matches the Agent call that returned this agentId"
        else "mismatch" end),
      parentAgentId: ($c.parentAgentId != null), description: ($c.description != null)}],
    session_ids: ([$ev[].session_id] | unique | length), session_id_is_main: ([$ev[].session_id] | unique == [$init.session_id]),
    prompt_ids: ([$ev[].prompt_id] | unique | length),
    subagent_events_with_agent_id: n(._where=="subagent"),
    denials: [$results[] | .permission_denials[]? | {tool: .tool_name, owner: ($owner[.tool_use_id] // "unknown")}],
    project_files: $r.project_files,
    verdict: {
      bash_ok_subagent: n(.hook_event_name=="PostToolUse" and .tool_name=="Bash" and ._where=="subagent" and probe_ok),
      bash_ok_main: n(.hook_event_name=="PostToolUse" and .tool_name=="Bash" and ._where=="main" and probe_ok),
      bash_attempt_subagent: n(.hook_event_name=="PreToolUse" and .tool_name=="Bash" and ._where=="subagent"),
      write_attempt_subagent: n(.hook_event_name=="PreToolUse" and .tool_name=="Write" and ._where=="subagent"),
      write_ok_subagent: n(.hook_event_name=="PostToolUse" and .tool_name=="Write" and ._where=="subagent"),
      write_attempt_main: n(.hook_event_name=="PreToolUse" and .tool_name=="Write" and ._where=="main"),
      probe_files_left: ([$r.project_files[] | select(startswith("probe-"))] | length),
      agent_pretooluse: n(.hook_event_name=="PreToolUse" and (.tool_name=="Agent" or .tool_name=="Task")),
      workflow_pretooluse: n(.hook_event_name=="PreToolUse" and .tool_name=="Workflow"),
      subagent_start: n(.hook_event_name=="SubagentStart"),
      denials_subagent: ([$results[] | .permission_denials[]? | select(($owner[.tool_use_id] // "main") != "main" and $owner[.tool_use_id] != null)] | length),
      denials_main: ([$results[] | .permission_denials[]? | select($owner[.tool_use_id] == "main")] | length),
      denials_unknown: ([$results[] | .permission_denials[]? | select($owner[.tool_use_id] == null)] | length),
      result_errors: ([$results[] | select(.is_error)] | length),
      bash_tool_use_in_subagent_transcripts: ([$sub[] | select(.type == "tool_use" and .name == "Bash") | .id] | unique | length),
      bash_refused_as_unavailable: ([$sub[] | select(.type == "tool_result" and ((.content | tostring) | contains("No such tool available: Bash"))) | .tool_use_id] | unique | length)
    }
  }'
