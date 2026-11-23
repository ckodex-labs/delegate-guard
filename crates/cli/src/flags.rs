//! Minimal flag parsing with Go `flag` package syntax, so existing hook
//! commands keep working: `-name value`, `--name value`, `-name=value`,
//! `--name=value`. Unknown flags, missing values, non-UTF-8 and positional
//! arguments are errors.

use std::collections::BTreeMap;
use std::ffi::OsString;

/// Parsed flag values by name.
#[derive(Debug, Default)]
pub(crate) struct Flags(BTreeMap<String, String>);

impl Flags {
    pub(crate) fn parse(args: &[OsString], known: &[&str]) -> Result<Flags, String> {
        let mut out = BTreeMap::new();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let arg = arg.to_str().ok_or("argument is not valid UTF-8")?;
            let Some(body) = arg
                .strip_prefix("--")
                .or_else(|| arg.strip_prefix('-'))
                .filter(|b| !b.is_empty())
            else {
                return Err(format!("unexpected argument {arg:?}"));
            };
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (body, None),
            };
            if !known.contains(&name) {
                return Err(format!("flag provided but not defined: -{name}"));
            }
            let value = match inline {
                Some(v) => v,
                None => it
                    .next()
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| format!("flag needs an argument: -{name}"))?
                    .to_owned(),
            };
            out.insert(name.to_owned(), value);
        }
        Ok(Flags(out))
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn test_flags_parse_accepts_go_forms() {
        let f = Flags::parse(&args(&["-policy", "p", "--state=s"]), &["policy", "state"]).unwrap();
        assert_eq!((f.get("policy"), f.get("state")), (Some("p"), Some("s")));
        let f = Flags::parse(&args(&["--policy", "p", "-state=s"]), &["policy", "state"]).unwrap();
        assert_eq!((f.get("policy"), f.get("state")), (Some("p"), Some("s")));
    }

    #[test]
    fn test_flags_parse_rejects_unknown_missing_and_positional() {
        for bad in [&["--nope", "x"][..], &["--policy"], &["stray"], &["-"]] {
            assert!(Flags::parse(&args(bad), &["policy"]).is_err(), "{bad:?}");
        }
    }
}
