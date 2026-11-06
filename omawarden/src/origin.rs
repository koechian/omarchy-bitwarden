/// Reports whether two URLs share a web origin: the same scheme, host and
/// effective port. Unparseable input never matches.
pub fn is_same_origin(u1_str: &str, u2_str: &str) -> bool {
    match (url::Url::parse(u1_str), url::Url::parse(u2_str)) {
        (Ok(u1), Ok(u2)) => {
            u1.scheme() == u2.scheme()
                && u1.host() == u2.host()
                && u1.port_or_known_default() == u2.port_or_known_default()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_same_origin() {
        let base = "https://vault.example.com";

        // Same origin paths and subpaths
        assert!(is_same_origin("https://vault.example.com/api/sync", base));
        assert!(is_same_origin(
            "https://vault.example.com/identity/connect/token",
            base
        ));

        // Prefix match on different domain must FAIL (mitigates credential exfiltration)
        assert!(!is_same_origin(
            "https://vault.example.com.attacker.com/leak",
            base
        ));
        assert!(!is_same_origin(
            "https://vault.example.com-evil.org/download",
            base
        ));

        // Different subdomain
        assert!(!is_same_origin("https://evil.example.com", base));

        // Different scheme
        assert!(!is_same_origin("http://vault.example.com", base));

        // Different port
        assert!(!is_same_origin("https://vault.example.com:8443", base));
    }
}
