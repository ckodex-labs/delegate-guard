//! Decision rules end to end through `handle`, with real state and receipt files.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod fixture;

use std::fs;

use delegate_guard_kernel::session::MAIN_ACTOR;
use delegate_guard_receipt as receipt;
use delegate_guard_state as state;
use fixture::{Env, mins, must_deny, must_pass, pol, profile, t0};

/// Positive control: the normal flow passes and leaves a verifiable receipt chain.
#[test]
fn test_handle_positive_flow_passes_and_chains() {
    let e = Env::new();
    must_pass(&e.tool("", "Read", t0()));
    must_pass(&e.spawn("", "Explore", t0()));
    let r = e.start("agent-a", "Explore", t0());
    assert!(
        r.exit == 0 && r.stdout.contains("additionalContext") && r.stdout.contains("Budget: 5"),
        "{r:?}"
    );
    must_pass(&e.tool("agent-a", "Grep", t0()));
    must_pass(&e.stop("agent-a", "Explore", t0()));
    assert_eq!(
        receipt::verify(&state::paths(&e.dir, &e.sid).receipts).unwrap(),
        5
    );
}

#[test]
fn test_root_unlisted_tool_denied() {
    must_deny(
        &Env::new().tool("", "Write", t0()),
        r#"tool "Write" is not in the grant"#,
    );
}

#[test]
fn test_spawn_unknown_type_denied() {
    must_deny(
        &Env::new().spawn("", "Plan", t0()),
        r#"no delegation profile for subagent_type "Plan""#,
    );
}

/// The profile asks for Write, the parent does not hold it: the child must not get it.
#[test]
fn test_child_tool_parent_lacks_denied() {
    let e = Env::new();
    must_pass(&e.spawn("", "Explore", t0()));
    e.start("agent-a", "Explore", t0());
    must_deny(
        &e.tool("agent-a", "Write", t0()),
        r#"tool "Write" is not in the grant"#,
    );
    must_deny(
        &e.tool("agent-a", "Bash", t0()),
        r#"tool "Bash" is not in the grant"#,
    );
}

#[test]
fn test_unbound_agent_denied() {
    let e = Env::new();
    e.start("rogue", "Explore", t0()); // no admitted spawn: stays unbound
    must_deny(&e.tool("rogue", "Read", t0()), "no admitted delegation");
}

/// Budget is shared, not copied: reservations come out of the parent's pool.
#[test]
fn test_budget_reserved_from_parent() {
    let e = Env::new();
    must_pass(&e.spawn("", "Explore", t0())); // root 30 → 30-1-5 = 24
    assert_eq!(e.session().agents[MAIN_ACTOR].remaining, 24);
    e.start("agent-a", "Explore", t0());
    for _ in 0..5 {
        must_pass(&e.tool("agent-a", "Read", t0()));
    }
    must_deny(
        &e.tool("agent-a", "Read", t0()),
        r#"budget for "agent-a" exhausted"#,
    );
}

/// Fan-out: children together can never hold more than the parent had.
#[test]
fn test_fan_out_cannot_exceed_parent() {
    let mut e = Env::new();
    e.p.root.max_calls = 14; // 14 = 2 × (1 + 5) + 2
    must_pass(&e.spawn("", "Explore", t0()));
    must_pass(&e.spawn("", "Explore", t0()));
    must_pass(&e.spawn("", "Explore", t0())); // 2 left: 1 for the call, 1 for the child
    let s = e.session();
    let reserved: i64 = s.pending.iter().map(|p| p.grant.max_calls).sum();
    assert!(
        reserved + 3 <= 14 && s.agents[MAIN_ACTOR].remaining == 0,
        "reserved {reserved}"
    );
    must_deny(&e.spawn("", "Explore", t0()), "budget");
}

#[test]
fn test_child_grant_expires() {
    let e = Env::new();
    must_pass(&e.spawn("", "Explore", t0()));
    e.start("agent-a", "Explore", t0());
    must_pass(&e.tool("agent-a", "Read", t0() + mins(9)));
    must_deny(&e.tool("agent-a", "Read", t0() + mins(10)), "expired");
    must_pass(&e.tool("", "Read", t0() + mins(10))); // parent unaffected
}

#[test]
fn test_stopped_agent_closed_and_refunded() {
    let e = Env::new();
    must_pass(&e.spawn("", "Explore", t0())); // main 24
    e.start("agent-a", "Explore", t0());
    must_pass(&e.tool("agent-a", "Read", t0())); // child 4 left
    must_pass(&e.stop("agent-a", "Explore", t0()));
    assert_eq!(
        e.session().agents[MAIN_ACTOR].remaining,
        28,
        "unused 4 calls return to parent"
    );
    must_deny(&e.tool("agent-a", "Read", t0()), "stopped");
}

#[test]
fn test_depth_limit_leaf_cannot_spawn() {
    let mut e = Env::new();
    e.p.root.max_calls = 100;
    must_pass(&e.spawn("", "general-purpose", t0())); // depth 1, holds Agent
    e.start("gp-1", "general-purpose", t0());
    must_pass(&e.spawn("gp-1", "general-purpose", t0())); // depth 2 = max: leaf, Agent removed
    e.start("gp-2", "general-purpose", t0());
    assert!(
        !e.session().agents["gp-2"].grant.has("Agent"),
        "leaf must not hold Agent"
    );
    must_deny(
        &e.spawn("gp-2", "general-purpose", t0()),
        r#"tool "Agent" is not in the grant"#,
    );
}

/// Two different parents spawn the same type before either child starts. The
/// hook payloads have no `agent_id` ↔ `tool_use_id` link, so both children must
/// get no more than the meet of the two candidate grants.
#[test]
fn test_ambiguous_parents_get_meet() {
    let mut e = Env::new();
    e.p.root.max_calls = 100;
    // gp-1 holds no Bash and only 6 calls, so its Explore child is weaker than main's.
    e.p.profiles.insert(
        "general-purpose".into(),
        profile(&["Agent", "Grep", "Read"], 6, mins(5)),
    );
    e.p.profiles.insert(
        "Explore".into(),
        profile(&["Grep", "Read", "Bash"], 8, mins(10)),
    );

    must_pass(&e.spawn("", "general-purpose", t0()));
    e.start("gp-1", "general-purpose", t0());
    // main's Explore child: [Bash Grep Read], 8 calls, 10m.
    // gp-1's Explore child: [Grep Read], 5 calls (6 - 1 for the Agent call), ≤ 5m.
    must_pass(&e.spawn("", "Explore", t0()));
    must_pass(&e.spawn("gp-1", "Explore", t0()));
    e.start("ex-1", "Explore", t0());
    e.start("ex-2", "Explore", t0());

    let s = e.session();
    for id in ["ex-1", "ex-2"] {
        let a = &s.agents[id];
        assert!(a.ambiguous, "{id} must be bound as ambiguous: {a:?}");
        assert!(
            !a.grant.has("Bash") && a.grant.max_calls <= 5 && a.grant.expires_at <= t0() + mins(5),
            "{id}: {a:?}"
        );
    }
    must_deny(
        &e.tool("ex-2", "Bash", t0()),
        r#"tool "Bash" is not in the grant"#,
    );

    // Conservation: 100 minus the 3 spawn calls must still be held or refunded.
    let total: i64 = [MAIN_ACTOR, "gp-1", "ex-1", "ex-2"]
        .iter()
        .map(|id| s.agents[*id].remaining)
        .sum();
    assert_eq!(total, 97, "budget not conserved");
}

#[test]
fn test_stale_pending_refunded() {
    let e = Env::new();
    must_pass(&e.spawn("", "Explore", t0())); // main 24, 5 reserved
    must_pass(&e.tool("", "Read", t0() + mins(3)));
    let s = e.session();
    assert!(
        s.pending.is_empty() && s.agents[MAIN_ACTOR].remaining == 28,
        "{s:?}"
    );
    e.start("late", "Explore", t0() + mins(3));
    must_deny(
        &e.tool("late", "Read", t0() + mins(3)),
        "no admitted delegation",
    );
}

#[test]
fn test_internal_error_fails_closed() {
    let mut e = Env::new();
    let blocker = e.dir.join("file");
    fs::write(&blocker, b"x").unwrap();
    e.dir = blocker.join("sub"); // creating a directory under a regular file fails
    must_deny(&e.tool("", "Read", t0()), "failing closed");
    let stop = e.stop("x", "Explore", t0());
    assert_eq!(
        stop.exit, 1,
        "SubagentStop must never exit 2 (it would keep the subagent running)"
    );
    assert_eq!(e.start("x", "Explore", t0()).exit, 1);
}

#[test]
fn test_policy_validation_lists_every_violation() {
    let mut bad = pol();
    bad.root.tools = vec!["*".into()];
    bad.profiles
        .insert("x".into(), delegate_guard_hook::Profile::default());
    let err = bad.validate().unwrap_err().to_string();
    assert!(
        err.contains(r#""*" not allowed"#) && err.contains("profiles.x"),
        "{err}"
    );
}

#[test]
fn test_policy_load_rejects_unknown_field() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("p.json");
    fs::write(&p, r#"{"root":{"tools":["Read"],"max_calls":1,"ttl":"1h"},"max_depth":1,"pending_ttl":"1m","profiles":{},"sidecar_bindng":true}"#).unwrap();
    let err = delegate_guard_hook::load_policy(&p)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown field"), "{err}");
}

#[test]
fn test_policy_load_accepts_shipped_examples() {
    for f in ["policy.json", "policy.sidecar.json"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(f);
        delegate_guard_hook::load_policy(&path).unwrap_or_else(|e| panic!("{f}: {e}"));
    }
}

#[test]
fn test_spawn_bad_tool_input_denied() {
    let e = Env::new();
    let i = delegate_guard_hook::Input {
        tool_name: "Agent".into(),
        tool_input: serde_json::json!({"subagent_type": 7}),
        ..e.input("PreToolUse", "")
    };
    must_deny(&e.run(&i, t0()), "cannot parse Agent tool_input");
}
