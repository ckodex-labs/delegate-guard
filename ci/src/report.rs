//! The gate report: one line per gate, sorted by name, failures named.

use std::fmt::Write;

/// Renders gate results sorted by name and returns the failed gate names.
pub fn render(mut results: Vec<(&'static str, Result<(), String>)>) -> (String, Vec<&'static str>) {
    results.sort_by_key(|(name, _)| *name);
    let mut text = String::new();
    let mut failed = Vec::new();
    for (name, result) in results {
        match result {
            Ok(()) => {
                let _ = writeln!(text, "ok   {name}"); // writing to a String cannot fail
            }
            Err(e) => {
                failed.push(name);
                let _ = writeln!(text, "FAIL {name}: {e}");
            }
        }
    }
    (text, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed gate must be named whatever its position; otherwise `check`
    /// would exit 0 on a red gate.
    #[test]
    fn test_render_names_every_failure_in_sorted_order() {
        let (text, failed) = render(vec![
            ("test", Err("exit 101".to_owned())),
            ("clippy", Ok(())),
            ("audit", Err("advisory".to_owned())),
        ]);
        assert_eq!(failed, vec!["audit", "test"]);
        assert_eq!(
            text,
            "FAIL audit: advisory\nok   clippy\nFAIL test: exit 101\n"
        );
    }

    #[test]
    fn test_render_all_ok_has_no_failures() {
        let (_, failed) = render(vec![("fmt", Ok(())), ("deny", Ok(()))]);
        assert!(failed.is_empty());
    }
}
