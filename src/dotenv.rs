//! Reading and writing `.env` files. `cemi import` reads them; the `dotenv`
//! destination updates one variable in place, keeping comments and order.

use anyhow::{Context, Result, anyhow, bail};

pub fn check_var_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        bail!("{name:?} is not a valid environment variable name (letters, digits and _)");
    }
    Ok(())
}

/// One variable found in a file, with the lines it spans (0-based, inclusive).
struct Entry {
    key: String,
    value: String,
    first_line: usize,
    last_line: usize,
}

fn entries(text: &str) -> Result<Vec<Entry>> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut n = 0;
    while n < lines.len() {
        let first = n;
        let line = lines[n].trim();
        n += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (key, rest) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("line {}: expected KEY=VALUE", first + 1))?;
        let key = key.trim().to_string();
        check_var_name(&key).with_context(|| format!("line {}", first + 1))?;
        let rest = rest.trim_start();
        let value = if let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') {
            let mut body = rest[1..].to_string();
            // Quoted values may span lines.
            while closing_index(&body, q).is_none() {
                match lines.get(n) {
                    Some(more) => {
                        body.push('\n');
                        body.push_str(more);
                        n += 1;
                    }
                    None => bail!("line {}: unclosed quote", first + 1),
                }
            }
            let end = closing_index(&body, q).expect("checked");
            if q == '"' {
                unescape(&body[..end])
            } else {
                body[..end].to_string()
            }
        } else {
            // Unquoted: drop a trailing comment.
            match rest.find(" #") {
                Some(i) => rest[..i].trim_end().to_string(),
                None => rest.trim_end().to_string(),
            }
        };
        out.push(Entry {
            key,
            value,
            first_line: first,
            last_line: n - 1,
        });
    }
    Ok(out)
}

/// Parses a .env file. Supports `export`, quotes, comments and escapes.
pub fn parse(text: &str) -> Result<Vec<(String, String)>> {
    Ok(entries(text)?
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect())
}

/// The value of `key` in a .env text (the last one wins, like most loaders).
pub fn get(text: &str, key: &str) -> Result<Option<String>> {
    Ok(entries(text)?
        .into_iter()
        .rev()
        .find(|e| e.key == key)
        .map(|e| e.value))
}

/// Returns `text` with `key` set to `value`: the existing line is replaced in
/// place (every copy, if repeated), or a new line is added at the end.
pub fn set(text: &str, key: &str, value: &str) -> Result<String> {
    check_var_name(key)?;
    let found = entries(text)?;
    let line = format!("{key}={}", quote(value));
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 1);
    let mut replaced = false;
    let mut i = 0;
    while i < lines.len() {
        if let Some(e) = found.iter().find(|e| e.first_line == i && e.key == key) {
            if !replaced {
                let exported = lines[i].trim_start().starts_with("export ");
                out.push(if exported {
                    format!("export {line}")
                } else {
                    line.clone()
                });
                replaced = true;
            }
            i = e.last_line + 1;
            continue;
        }
        out.push(lines[i].to_string());
        i += 1;
    }
    if !replaced {
        out.push(line);
    }
    let mut s = out.join("\n");
    s.push('\n');
    Ok(s)
}

/// Writes a value so that `parse` reads it back unchanged: bare when safe,
/// single quotes when possible (no escapes, no `$` expansion in most loaders),
/// double quotes with escapes otherwise.
pub fn quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.,:/@+=%~^".contains(c));
    if safe {
        return value.to_string();
    }
    if !value.contains('\'') && !value.contains('\n') && !value.contains('\r') {
        return format!("'{value}'");
    }
    let mut s = String::with_capacity(value.len() + 2);
    s.push('"');
    for c in value.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

fn unescape(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn closing_index(body: &str, q: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        if q == '"' && c == '\\' && !escaped {
            escaped = true;
            continue;
        }
        if c == q && !escaped {
            return Some(i);
        }
        escaped = false;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dotenv() {
        let text = "# comment\nA=1\nexport B = two words # note\nC=\"x\\ny\"\nD='it''s'\nE=\"multi\nline\"\nF=\nG=\"a\\\\nb\"\n";
        let v = parse(text).unwrap();
        assert_eq!(v[0], ("A".into(), "1".into()));
        assert_eq!(v[1], ("B".into(), "two words".into()));
        assert_eq!(v[2], ("C".into(), "x\ny".into()));
        assert_eq!(v[3], ("D".into(), "it".into()));
        assert_eq!(v[4], ("E".into(), "multi\nline".into()));
        assert_eq!(v[5], ("F".into(), "".into()));
        // An escaped backslash followed by n is not a newline.
        assert_eq!(v[6], ("G".into(), "a\\nb".into()));
        assert!(parse("1A=x").is_err());
    }

    #[test]
    fn quoted_values_read_back_unchanged() {
        for value in [
            "plain_value-1.2",
            "has spaces",
            "dollar $HOME and # hash",
            "it's",
            "line one\nline two",
            "back\\slash \"quoted\" it's",
            "",
        ] {
            let text = format!("K={}\n", quote(value));
            assert_eq!(get(&text, "K").unwrap().as_deref(), Some(value), "{text}");
        }
    }

    #[test]
    fn set_replaces_in_place_and_keeps_the_rest() {
        let text = "# db\nA=1\nexport KEY=\"old\nvalue\"\nB=2\nKEY=dup\n";
        let out = set(text, "KEY", "new one").unwrap();
        assert_eq!(out, "# db\nA=1\nexport KEY='new one'\nB=2\n");
        let out = set("A=1", "NEW", "x").unwrap();
        assert_eq!(out, "A=1\nNEW=x\n");
    }
}
