use super::*;

fn t0() -> Timestamp {
    "2026-11-22T10:00:00Z".parse().unwrap()
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

fn root() -> Grant {
    Grant {
        tools: s(&["Agent", "Bash", "Glob", "Grep", "Read"]),
        max_calls: 100,
        expires_at: t0() + SignedDuration::from_hours(1),
        depth: 0,
    }
}

fn req(tools: &[&str], max_calls: i64, ttl: SignedDuration) -> Request {
    Request {
        tools: s(tools),
        max_calls,
        ttl,
    }
}

#[test]
fn test_attenuate_narrows_tools() {
    let c = attenuate(
        &root(),
        100,
        &req(&["Read", "Write", "Grep"], 10, SignedDuration::from_mins(1)),
        2,
        t0(),
    )
    .unwrap();
    assert_eq!(
        c.tools,
        s(&["Grep", "Read"]),
        "Write is not held by the parent"
    );
}

#[test]
fn test_attenuate_budget_capped_by_parent_remaining() {
    let c = attenuate(
        &root(),
        7,
        &req(&["Read"], 50, SignedDuration::from_mins(1)),
        2,
        t0(),
    )
    .unwrap();
    assert_eq!(c.max_calls, 7);
}

#[test]
fn test_attenuate_expiry_capped_by_parent() {
    let c = attenuate(
        &root(),
        100,
        &req(&["Read"], 1, SignedDuration::from_hours(24)),
        2,
        t0(),
    )
    .unwrap();
    assert_eq!(c.expires_at, root().expires_at);
}

#[test]
fn test_attenuate_leaf_cannot_spawn() {
    let c = attenuate(
        &root(),
        100,
        &req(&["Agent", "Read"], 5, SignedDuration::from_mins(1)),
        1,
        t0(),
    )
    .unwrap();
    assert!(
        !c.has(SPAWN_TOOL),
        "child at max depth must not hold Agent: {:?}",
        c.tools
    );
}

type RejectCase = (&'static str, Grant, i64, Request, i64, AttenuateError);

/// Cases the request alone makes invalid:
/// (name, parent, parent remaining, request, max depth, expected error).
fn request_rejections() -> Vec<RejectCase> {
    let min = SignedDuration::from_mins(1);
    vec![
        (
            "no tools requested",
            root(),
            10,
            req(&[], 1, min),
            2,
            AttenuateError::NoTools,
        ),
        (
            "disjoint tools",
            root(),
            10,
            req(&["Write"], 1, min),
            2,
            AttenuateError::EmptyGrant,
        ),
        (
            "zero budget request",
            root(),
            10,
            req(&["Read"], 0, min),
            2,
            AttenuateError::BadRequest,
        ),
        (
            "negative ttl",
            root(),
            10,
            req(&["Read"], 1, SignedDuration::from_secs(-1)),
            2,
            AttenuateError::BadRequest,
        ),
    ]
}

/// Cases the parent's state makes invalid.
fn parent_rejections() -> Vec<RejectCase> {
    let mut expired = root();
    expired.expires_at = t0();
    let mut deep = root();
    deep.depth = 2;
    let min = SignedDuration::from_mins(1);
    vec![
        (
            "only Agent at leaf depth",
            root(),
            10,
            req(&["Agent"], 1, min),
            1,
            AttenuateError::EmptyGrant,
        ),
        (
            "parent budget exhausted",
            root(),
            0,
            req(&["Read"], 1, min),
            2,
            AttenuateError::Budget,
        ),
        (
            "parent expired",
            expired,
            10,
            req(&["Read"], 1, min),
            2,
            AttenuateError::ParentExpiry,
        ),
        (
            "depth exceeded",
            deep,
            10,
            req(&["Read"], 1, min),
            2,
            AttenuateError::Depth { child: 3, max: 2 },
        ),
    ]
}

#[test]
fn test_attenuate_rejects_each_rule() {
    for (name, parent, rem, r, max_depth, want) in
        request_rejections().into_iter().chain(parent_rejections())
    {
        assert_eq!(
            attenuate(&parent, rem, &r, max_depth, t0()),
            Err(want),
            "{name}"
        );
    }
}

/// Deterministic generator (splitmix64) so the property test is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, n).
    fn int(&mut self, n: i64) -> i64 {
        i64::try_from(self.next() % n.unsigned_abs()).unwrap()
    }
}

const UNIVERSE: [&str; 9] = [
    "Agent",
    "Bash",
    "Edit",
    "Glob",
    "Grep",
    "Read",
    "WebFetch",
    "Write",
    "mcp__x__y",
];

fn pick(rng: &mut Rng) -> Vec<String> {
    UNIVERSE
        .iter()
        .filter(|_| rng.int(2) == 0)
        .map(|x| (*x).to_owned())
        .collect()
}

/// A random (parent, parent remaining, request, max depth), including invalid ones.
fn random_case(rng: &mut Rng) -> (Grant, i64, Request, i64) {
    let parent = Grant {
        tools: pick(rng),
        max_calls: rng.int(50),
        expires_at: t0() + SignedDuration::from_secs(rng.int(7200) - 600),
        depth: rng.int(4),
    };
    let rem = rng.int(parent.max_calls + 1);
    let request = Request {
        tools: pick(rng),
        max_calls: rng.int(80) - 5,
        ttl: SignedDuration::from_secs(rng.int(10_000) - 100),
    };
    (parent, rem, request, rng.int(4))
}

/// Every axis of `child` is within `parent`.
fn assert_within(i: usize, parent: &Grant, rem: i64, max_depth: i64, child: &Grant) {
    for tool in &child.tools {
        assert!(
            parent.has(tool),
            "case {i}: child tool {tool:?} not held by parent {:?}",
            parent.tools
        );
    }
    assert!(
        child.max_calls > 0 && child.max_calls <= rem,
        "case {i}: child budget {} outside (0, {rem}]",
        child.max_calls
    );
    assert!(
        child.expires_at <= parent.expires_at && child.expires_at > t0(),
        "case {i}: child expiry out of (now, parent]"
    );
    assert!(
        child.depth == parent.depth + 1 && child.depth <= max_depth,
        "case {i}: bad depth {}",
        child.depth
    );
    assert!(
        !(child.has(SPAWN_TOOL) && child.depth >= max_depth),
        "case {i}: leaf holds Agent"
    );
}

/// Randomized property test over 200k cases: whenever `attenuate` succeeds,
/// the child is a subset of the parent on every axis.
#[test]
fn test_attenuate_never_amplifies() {
    let mut rng = Rng(42);
    let mut ok = 0;
    for i in 0..200_000 {
        let (parent, rem, request, max_depth) = random_case(&mut rng);
        let Ok(child) = attenuate(&parent, rem, &request, max_depth, t0()) else {
            continue;
        };
        ok += 1;
        assert_within(i, &parent, rem, max_depth, &child);
    }
    assert!(
        ok >= 1000,
        "generator too restrictive: only {ok} successful cases"
    );
    println!("property held on {ok} successful attenuations out of 200000 generated");
}

#[test]
fn test_meet_is_subset_of_all() {
    let a = Grant {
        tools: s(&["Bash", "Read"]),
        max_calls: 10,
        expires_at: t0() + SignedDuration::from_hours(1),
        depth: 1,
    };
    let b = Grant {
        tools: s(&["Grep", "Read"]),
        max_calls: 4,
        expires_at: t0() + SignedDuration::from_mins(1),
        depth: 2,
    };
    let m = a.meet(&b);
    assert_eq!(
        m,
        Grant {
            tools: s(&["Read"]),
            max_calls: 4,
            expires_at: b.expires_at,
            depth: 2
        }
    );
}
