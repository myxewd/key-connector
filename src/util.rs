use std::sync::LockResult;

/// Normalizes an API prefix taken from the environment.
///
/// The result is either empty (serve at the root) or of the form "/sub/path":
/// a single leading slash, no trailing slash, and surrounding whitespace
/// removed. This is what gets prepended to every route.
pub fn normalize_api_prefix(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
    }
}

/// Removes credentials from a database URL before it is written to a log.
///
/// Userinfo passwords and password-like query parameters are replaced with
/// "***". URLs without credentials are returned unchanged.
pub fn redact_database_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let authority = match authority.rsplit_once('@') {
        Some((userinfo, host)) => match userinfo.split_once(':') {
            Some((user, _password)) => format!("{user}:***@{host}"),
            None => format!("{userinfo}@{host}"),
        },
        None => authority.to_string(),
    };
    format!("{scheme}{authority}{}", redact_query(tail))
}

fn redact_query(tail: &str) -> String {
    const SENSITIVE: [&str; 5] = ["password", "passwd", "pwd", "secret", "token"];
    let Some((path, query)) = tail.split_once('?') else {
        return tail.to_string();
    };
    let redacted = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _value))
                if SENSITIVE
                    .iter()
                    .any(|needle| key.to_ascii_lowercase().contains(needle)) =>
            {
                format!("{key}=***")
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{redacted}")
}

/// Takes a lock guard even if the lock was poisoned by a panicking thread.
///
/// The verifier's key is swapped from a background task; a panic while that
/// lock is held must not take down every later request.
pub fn recover_lock<T>(result: LockResult<T>) -> T {
    result.unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn prefixes_are_normalized() {
        assert_eq!(normalize_api_prefix(""), "");
        assert_eq!(normalize_api_prefix("   "), "");
        assert_eq!(normalize_api_prefix("/"), "");
        assert_eq!(normalize_api_prefix("kc"), "/kc");
        assert_eq!(normalize_api_prefix("/kc"), "/kc");
        assert_eq!(normalize_api_prefix("/kc/"), "/kc");
        assert_eq!(normalize_api_prefix("  /api/kc/  "), "/api/kc");
        assert_eq!(normalize_api_prefix("///kc//"), "/kc");
    }

    #[test]
    fn passwords_are_redacted_from_database_urls() {
        assert_eq!(
            redact_database_url("postgres://user:s3cret@db:5432/vault?sslmode=require"),
            "postgres://user:***@db:5432/vault?sslmode=require"
        );
        assert_eq!(
            redact_database_url("postgres://user:pass@db/vault?password=other"),
            "postgres://user:***@db/vault?password=***"
        );
        assert_eq!(
            redact_database_url("postgres://user@db/vault"),
            "postgres://user@db/vault"
        );
    }

    #[test]
    fn plain_urls_are_left_alone() {
        assert_eq!(
            redact_database_url("sqlite://keyconnector.db?mode=rwc"),
            "sqlite://keyconnector.db?mode=rwc"
        );
        assert_eq!(redact_database_url("sqlite::memory:"), "sqlite::memory:");
        assert_eq!(
            redact_database_url("postgres://db:5432/vault"),
            "postgres://db:5432/vault"
        );
    }

    #[test]
    fn recover_lock_survives_poisoning() {
        let mutex = Arc::new(Mutex::new(7u8));
        let handle = Arc::clone(&mutex);
        let _ = std::thread::spawn(move || {
            let _guard = handle.lock().unwrap();
            panic!("poison the lock");
        })
        .join();

        assert!(mutex.lock().is_err(), "lock should be poisoned");
        let guard = recover_lock(mutex.lock());
        assert_eq!(*guard, 7);
    }
}
