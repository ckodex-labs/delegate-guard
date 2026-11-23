use std::fs;

use super::*;

fn write3() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("r.jsonl");
    for d in [Decision::Deny, Decision::Pass, Decision::Deny] {
        append(
            &p,
            Entry::new(
                Timestamp::UNIX_EPOCH,
                Fact::new("PreToolUse", "main", d).tool("Bash"),
            ),
        )
        .unwrap();
    }
    (dir, p)
}

fn lines(p: &Path) -> Vec<String> {
    fs::read_to_string(p)
        .unwrap()
        .split_inclusive('\n')
        .map(str::to_owned)
        .collect()
}

#[test]
fn test_verify_intact_chain_passes() {
    let (_d, p) = write3();
    assert_eq!(verify(&p).unwrap(), 3);
    assert_eq!(head(&p).unwrap().0, 3);
}

#[test]
fn test_verify_missing_log_is_empty() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(verify(&d.path().join("none")).unwrap(), 0);
    assert_eq!(
        head(&d.path().join("none")).unwrap(),
        (0, GENESIS.to_owned())
    );
}

#[test]
fn test_verify_detects_edit() {
    let (_d, p) = write3();
    let b = fs::read_to_string(&p).unwrap();
    fs::write(
        &p,
        b.replacen(r#""decision":"deny""#, r#""decision":"pass""#, 1),
    )
    .unwrap();
    let f = verify(&p).unwrap_err();
    assert!(matches!(f.error, ReceiptError::Hash { seq: 1 }), "{f}");
    assert_eq!(f.valid, 0);
}

#[test]
fn test_verify_detects_deletion() {
    let (_d, p) = write3();
    let l = lines(&p);
    fs::write(&p, format!("{}{}", l[0], l[2])).unwrap();
    let f = verify(&p).unwrap_err();
    assert_eq!(f.valid, 1, "{f}");
}

#[test]
fn test_verify_detects_reorder() {
    let (_d, p) = write3();
    let l = lines(&p);
    fs::write(&p, format!("{}{}{}", l[1], l[0], l[2])).unwrap();
    assert!(verify(&p).is_err());
}

/// An extra key leaves every hashed field intact; only the canonical-form
/// check catches it.
#[test]
fn test_verify_detects_injected_field() {
    let (_d, p) = write3();
    let b = fs::read_to_string(&p).unwrap();
    fs::write(
        &p,
        b.replacen(r#"{"seq":2,"#, r#"{"seq":2,"approved_by":"admin","#, 1),
    )
    .unwrap();
    let f = verify(&p).unwrap_err();
    assert!(
        matches!(f.error, ReceiptError::NonCanonical { seq: 2 }),
        "{f}"
    );
    assert_eq!(f.valid, 1);
}

#[test]
fn test_verify_rejects_garbage_line() {
    let (_d, p) = write3();
    let mut b = fs::read_to_string(&p).unwrap();
    b.push_str("{not json\n");
    fs::write(&p, b).unwrap();
    assert!(matches!(
        verify(&p).unwrap_err().error,
        ReceiptError::Parse { line: 4, .. }
    ));
}

/// A record lifted from another log is self-consistent (its own seq and hash
/// check out); only the `prev_hash` link exposes it.
#[test]
fn test_verify_detects_record_spliced_from_other_log() {
    let (_d, a) = write3();
    let other = a.with_file_name("other.jsonl");
    for actor in ["intruder", "intruder"] {
        append(
            &other,
            Entry::new(
                Timestamp::UNIX_EPOCH,
                Fact::new("PreToolUse", actor, Decision::Pass),
            ),
        )
        .unwrap();
    }
    let (la, lb) = (lines(&a), lines(&other));
    fs::write(&a, format!("{}{}{}", la[0], lb[1], la[2])).unwrap();
    let f = verify(&a).unwrap_err();
    assert!(matches!(f.error, ReceiptError::PrevHash { seq: 2 }), "{f}");
    assert_eq!(f.valid, 1);
}
