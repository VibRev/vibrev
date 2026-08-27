//! The `Authorization` header half of HTTP bearer auth.
//!
//! [`crate::token`] owns the file — its format, its `0600`, its path, and the
//! constant-time comparison. What is here is the part that needs a request in
//! hand: reading the header and choosing what to answer.

use http::{HeaderMap, StatusCode, header::AUTHORIZATION};

use crate::token::Accepted;

/// Why a request was turned away, and what to answer it with.
///
/// **401, not 403.** The two are not interchangeable: 403 means "the server
/// understood who you are and refuses anyway", which is what the `Origin`/`Host`
/// policy says — no credential changes that answer. A missing or wrong bearer is
/// the other case, "authenticate and try again", which is 401 plus the
/// `WWW-Authenticate` challenge RFC 9110 requires on it. Keeping them distinct
/// also means an operator reading a log can tell a rebinding probe from a
/// credential failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BearerRejection {
    pub status: StatusCode,
    /// `WWW-Authenticate` value.
    pub challenge: &'static str,
    /// Response body. Fixed strings only — see [`validate`].
    pub message: &'static str,
}

const MISSING: BearerRejection = BearerRejection {
    status: StatusCode::UNAUTHORIZED,
    challenge: "Bearer",
    message: "Unauthorized: this endpoint requires an Authorization: Bearer credential",
};

const MALFORMED: BearerRejection = BearerRejection {
    status: StatusCode::UNAUTHORIZED,
    challenge: "Bearer error=\"invalid_request\"",
    message: "Unauthorized: the Authorization header is not a well-formed Bearer credential",
};

const INVALID: BearerRejection = BearerRejection {
    status: StatusCode::UNAUTHORIZED,
    challenge: "Bearer error=\"invalid_token\"",
    message: "Unauthorized: invalid bearer token",
};

/// Validate the `Authorization` header against the accepted set.
///
/// Every rejection message is a fixed string. Nothing derived from the stored
/// token — not its length, not a prefix, not "close but no" — goes into a
/// response, because an oracle that scores guesses defeats the constant-time
/// comparison [`Accepted::accepts`] does.
pub fn validate(accepted: &Accepted, headers: &HeaderMap) -> Result<(), BearerRejection> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Err(MISSING);
    };
    let Ok(value) = value.to_str() else {
        return Err(MALFORMED);
    };
    let Some(candidate) = strip_bearer(value) else {
        return Err(MALFORMED);
    };
    if accepted.accepts(candidate) {
        Ok(())
    } else {
        Err(INVALID)
    }
}

/// `Bearer <token>`, scheme matched case-insensitively per RFC 9110.
fn strip_bearer(value: &str) -> Option<&str> {
    let (scheme, credential) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let credential = credential.trim();
    (!credential.is_empty()).then_some(credential)
}

#[cfg(test)]
mod tests {
    use super::{strip_bearer, validate};
    use crate::token::Accepted;
    use http::{HeaderMap, StatusCode, header::AUTHORIZATION};

    fn accepted(tokens: &[&str]) -> Accepted {
        Accepted::new(tokens.iter().map(|t| (*t).to_string()).collect(), None)
            .expect("non-empty token set")
    }

    fn header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value.parse().expect("valid header"));
        headers
    }

    #[test]
    fn a_missing_header_is_401_with_a_challenge() {
        let rejection =
            validate(&accepted(&["vbr_a"]), &HeaderMap::new()).expect_err("no credential");
        assert_eq!(rejection.status, StatusCode::UNAUTHORIZED);
        assert_eq!(rejection.challenge, "Bearer");
    }

    #[test]
    fn a_wrong_token_is_401_and_the_body_says_nothing_about_the_real_one() {
        let rejection = validate(&accepted(&["vbr_secret"]), &header("Bearer vbr_guess"))
            .expect_err("wrong credential");
        assert_eq!(rejection.status, StatusCode::UNAUTHORIZED);
        assert!(!rejection.message.contains("vbr_secret"));
        assert!(!rejection.message.contains("10"), "no length hint");
    }

    #[test]
    fn a_non_bearer_scheme_is_rejected() {
        let accepted = accepted(&["vbr_secret"]);
        assert!(validate(&accepted, &header("Basic dXNlcjpwYXNz")).is_err());
        assert!(validate(&accepted, &header("Bearer")).is_err());
        assert!(validate(&accepted, &header("Bearer   ")).is_err());
    }

    #[test]
    fn the_bearer_scheme_is_case_insensitive() {
        let accepted = accepted(&["vbr_secret"]);
        assert!(validate(&accepted, &header("bearer vbr_secret")).is_ok());
        assert!(validate(&accepted, &header("BEARER vbr_secret")).is_ok());
    }

    #[test]
    fn a_correct_token_passes() {
        assert!(validate(&accepted(&["vbr_secret"]), &header("Bearer vbr_secret")).is_ok());
    }

    /// A rotation leaves the outgoing token on a later line of the file. That
    /// the file is a list is `token`'s business; that the *listener* reaches
    /// past line one is this module's, and it is the only reason the list
    /// format buys anything.
    #[test]
    fn a_token_from_a_later_line_still_authenticates() {
        let accepted = accepted(&["vbr_new", "vbr_old"]);
        assert!(validate(&accepted, &header("Bearer vbr_old")).is_ok());
        assert!(validate(&accepted, &header("Bearer vbr_new")).is_ok());
        assert!(validate(&accepted, &header("Bearer vbr_gone")).is_err());
    }

    #[test]
    fn strip_bearer_extracts_the_credential() {
        assert_eq!(strip_bearer("Bearer abc"), Some("abc"));
        assert_eq!(strip_bearer("Bearer  abc "), Some("abc"));
        assert_eq!(strip_bearer("Token abc"), None);
        assert_eq!(strip_bearer("abc"), None);
    }
}
