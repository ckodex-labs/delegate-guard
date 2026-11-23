//! Revocation on policy change: after the policy narrows, the next event of a
//! session narrows every issued grant to it. Each test changes `e.p` between
//! events, exactly as a daemon reload or an edited policy file would.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod fixture;

use delegate_guard_kernel::session::MAIN_ACTOR;
use delegate_guard_state as state;
use fixture::{Env, mins, must_deny, must_pass, profile, t0, tools};

fn receipts(e: &Env) -> String {
    std::fs::read_to_string(state::paths(&e.dir, &e.sid).receipts).unwrap()
}

fn spawn_explore(e: &Env) {
    must_pass(&e.spawn("", "Explore", t0()));
    e.start("ex", "Explore", t0());
}

#[test]
fn test_narrowing_root_tools_revokes_them_mid_session() {
    let mut e = Env::new();
    must_pass(&e.tool("", "Read", t0()));
    e.p.root.tools = tools(&["Agent", "Grep"]);
    must_deny(
        &e.tool("", "Read", t0()),
        r#"tool "Read" is not in the grant"#,
    );
    must_pass(&e.tool("", "Grep", t0()));
    let log = receipts(&e);
    assert!(
        log.contains(r#""decision":"revoke""#) && log.contains("narrowed: tools"),
        "{log}"
    );
    assert_eq!(
        delegate_guard_receipt::verify(&state::paths(&e.dir, &e.sid).receipts).unwrap(),
        4,
        "pass, revoke, deny, pass"
    );
}

#[test]
fn test_narrowing_a_profile_narrows_live_children() {
    let mut e = Env::new();
    spawn_explore(&e);
    must_pass(&e.tool("ex", "Grep", t0()));
    e.p.profiles
        .insert("Explore".into(), profile(&["Read"], 5, mins(10)));
    must_deny(
        &e.tool("ex", "Grep", t0()),
        r#"tool "Grep" is not in the grant"#,
    );
    must_pass(&e.tool("ex", "Read", t0()));
}

#[test]
fn test_removing_a_profile_revokes_its_agents() {
    let mut e = Env::new();
    spawn_explore(&e);
    e.p.profiles.remove("Explore");
    must_deny(
        &e.tool("ex", "Read", t0()),
        r#"grant for "ex" was revoked: no profile for subagent_type "Explore""#,
    );
    let s = e.session();
    assert_eq!(
        s.agents["ex"].remaining, 0,
        "a revoked grant keeps no budget"
    );
}

#[test]
fn test_lower_budget_caps_remaining() {
    let mut e = Env::new();
    spawn_explore(&e); // ex holds 5
    e.p.profiles.insert(
        "Explore".into(),
        profile(&["Glob", "Grep", "Read"], 2, mins(10)),
    );
    must_pass(&e.tool("ex", "Read", t0()));
    must_pass(&e.tool("ex", "Read", t0()));
    must_deny(&e.tool("ex", "Read", t0()), "exhausted (2 calls)");
}

#[test]
fn test_shorter_ttl_brings_expiry_forward() {
    let mut e = Env::new();
    spawn_explore(&e); // expires t0 + 10m
    e.p.profiles.insert(
        "Explore".into(),
        profile(&["Glob", "Grep", "Read"], 5, mins(1)),
    );
    must_pass(&e.tool("ex", "Read", t0() + mins(2))); // narrowing seen here: expiry now t0 + 3m
    must_deny(&e.tool("ex", "Read", t0() + mins(4)), "expired");
}

#[test]
fn test_lower_max_depth_removes_agent_and_revokes_too_deep() {
    let mut e = Env::new();
    e.p.root.max_calls = 100;
    must_pass(&e.spawn("", "general-purpose", t0()));
    e.start("gp-1", "general-purpose", t0()); // depth 1, holds Agent
    must_pass(&e.spawn("gp-1", "general-purpose", t0()));
    e.start("gp-2", "general-purpose", t0()); // depth 2
    e.p.max_depth = 1;
    must_deny(&e.tool("gp-2", "Read", t0()), "depth 2 exceeds max_depth 1");
    must_deny(
        &e.spawn("gp-1", "general-purpose", t0()),
        r#"tool "Agent" is not in the grant"#,
    );
    let gp1 = &e.session().agents["gp-1"];
    assert!(
        gp1.revoked.is_none() && !gp1.grant.has("Agent"),
        "gp-1 is now a leaf, not revoked: {gp1:?}"
    );
    // gp-2's 9 reserved calls are forfeited with it, not refunded to gp-1.
    assert_eq!(gp1.remaining, 0);
}

#[test]
fn test_revoked_parent_revokes_children() {
    let mut e = Env::new();
    e.p.root.max_calls = 100;
    e.p.profiles
        .insert("Explore".into(), profile(&["Agent", "Read"], 20, mins(10)));
    must_pass(&e.spawn("", "Explore", t0()));
    e.start("parent", "Explore", t0());
    must_pass(&e.spawn("parent", "general-purpose", t0()));
    e.start("child", "general-purpose", t0());
    e.p.profiles.remove("Explore");
    must_deny(
        &e.tool("child", "Read", t0()),
        r#"parent "parent" was revoked"#,
    );
}

#[test]
fn test_wider_policy_never_widens_issued_grants() {
    let mut e = Env::new();
    must_deny(&e.tool("", "Write", t0()), "not in the grant");
    e.p.root.tools.push("Write".into());
    must_deny(&e.tool("", "Write", t0()), "not in the grant");
    e.sid = "fresh".into();
    must_pass(&e.tool("", "Write", t0()));
}

#[test]
fn test_pending_spawn_of_removed_profile_is_dropped_and_refunded() {
    let mut e = Env::new();
    must_pass(&e.spawn("", "Explore", t0())); // main 30 → 24, 5 reserved
    e.p.profiles.remove("Explore");
    must_pass(&e.tool("", "Read", t0()));
    let s = e.session();
    assert!(s.pending.is_empty(), "the pending spawn must be dropped");
    assert_eq!(
        s.agents[MAIN_ACTOR].remaining, 28,
        "its 5 reserved calls return, minus this Read"
    );
    e.start("late", "Explore", t0());
    must_deny(&e.tool("late", "Read", t0()), "no admitted delegation");
}

#[test]
fn test_compliant_session_records_no_revocations() {
    let e = Env::new();
    spawn_explore(&e);
    for _ in 0..3 {
        must_pass(&e.tool("ex", "Read", t0()));
    }
    assert!(!receipts(&e).contains(r#""decision":"revoke""#));
}

#[test]
fn test_child_loses_tools_its_parent_lost() {
    let mut e = Env::new();
    spawn_explore(&e); // ex: [Glob Grep Read]; the Explore profile keeps Read below
    e.p.root.tools = tools(&["Agent", "Glob", "Grep"]);
    must_deny(
        &e.tool("ex", "Read", t0()),
        r#"tool "Read" is not in the grant"#,
    );
    must_pass(&e.tool("ex", "Grep", t0()));
}

#[test]
fn test_refund_after_narrowing_never_exceeds_the_new_budget() {
    let mut e = Env::new();
    spawn_explore(&e); // main 30 → 24, ex holds 5
    e.p.root.max_calls = 10;
    must_pass(&e.tool("", "Read", t0())); // main narrowed to 10, then spends 1 → 9
    must_pass(&e.stop("ex", "Explore", t0())); // 5 unused calls come back
    assert_eq!(
        e.session().agents[MAIN_ACTOR].remaining,
        10,
        "refunds stop at the narrowed max_calls"
    );
}

/// Events reach the session lock in any order, so an event can carry a clock
/// reading older than the one that issued a grant. An unchanged policy must
/// then record nothing: only a policy change may narrow.
#[test]
fn test_out_of_order_event_time_under_unchanged_policy_records_no_revoke() {
    let e = Env::new();
    let later = t0() + jiff::SignedDuration::from_millis(5);
    must_pass(&e.tool("", "Read", later)); // root grant issued at `later`
    must_pass(&e.tool("", "Read", t0())); // decided after, clock read before
    let log = receipts(&e);
    assert!(!log.contains(r#""decision":"revoke""#), "{log}");
    assert_eq!(
        delegate_guard_receipt::verify(&state::paths(&e.dir, &e.sid).receipts).unwrap(),
        2,
        "pass, pass"
    );
}
