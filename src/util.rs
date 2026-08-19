//! Small display / identity helpers shared by the library and the CLI.

/// First `n` chars of `s`, or the whole string if shorter. Never panics.
pub fn prefix(s: &str, n: usize) -> &str {
    s.get(..n).unwrap_or(s)
}

/// Truncate a command line for table display.
pub fn ellipsize(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_string();
    }
    let take = max_chars.saturating_sub(3);
    let mut out: String = s.chars().take(take).collect();
    out.push_str("...");
    out
}

/// Join argv for humans. Empty → em dash.
pub fn command_line(command: &[String]) -> String {
    if command.is_empty() {
        "—".to_string()
    } else {
        command.join(" ")
    }
}

/// Best-effort process actor (not an authn proof).
pub fn current_actor() -> Option<String> {
    std::env::var("SEL_DEPLOY_ACTOR")
        .ok()
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .filter(|s| !s.is_empty())
}

/// Best-effort hostname (not an attestation of the machine identity).
pub fn current_hostname() -> Option<String> {
    std::env::var("SEL_DEPLOY_HOSTNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
}

/// Current working directory as a string, if available.
pub fn current_cwd() -> Option<String> {
    std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_never_panics() {
        assert_eq!(prefix("abcdef", 3), "abc");
        assert_eq!(prefix("ab", 8), "ab");
        assert_eq!(prefix("", 4), "");
    }

    #[test]
    fn ellipsize_short_is_unchanged() {
        assert_eq!(ellipsize("hello", 10), "hello");
        assert_eq!(ellipsize("hello world", 8), "hello...");
    }
}
