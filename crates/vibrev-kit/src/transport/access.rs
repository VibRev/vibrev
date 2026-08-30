//! The one gate every HTTP request passes through.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::{
    body::Body as AxumBody,
    extract::{Request as AxumRequest, State},
    middleware::Next,
    response::Response as AxumResponse,
};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Response, StatusCode,
    header::{HOST, WWW_AUTHENTICATE},
};
use http_body_util::{BodyExt, Full, combinators::BoxBody};

use crate::token::Accepted;
use crate::transport::bearer;

type AccessResponse = Response<BoxBody<Bytes, Infallible>>;
type AccessError = Box<AccessResponse>;

/// Bearer authentication for one running listener.
#[derive(Clone, Debug)]
pub struct AccessPolicy {
    bind_addr: SocketAddr,
    allowed_hosts: HostAllowList,
    /// Not an `Option`. An absent token set would be an unauthenticated listener
    /// that still type-checks, and the invariant here is that no such listener
    /// exists: every constructor has to produce one.
    auth: Accepted,
}

impl AccessPolicy {
    pub fn new(bind_addr: SocketAddr, allow_host: Option<&[String]>, auth: Accepted) -> Self {
        Self {
            bind_addr,
            allowed_hosts: HostAllowList::from_cli(allow_host),
            auth,
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn auth(&self) -> &Accepted {
        &self.auth
    }

    pub fn host_check_disabled(&self) -> bool {
        matches!(self.allowed_hosts, HostAllowList::Any)
    }

    pub fn host_policy_summary(&self) -> String {
        match &self.allowed_hosts {
            HostAllowList::Any => "disabled; all Host values are allowed".to_string(),
            HostAllowList::Restricted(extra_hosts) if extra_hosts.is_empty() => {
                format!("bind-derived IP hosts for {}", self.bind_addr)
            }
            HostAllowList::Restricted(extra_hosts) => {
                let extra = extra_hosts
                    .iter()
                    .map(NormalizedAuthority::display)
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "bind-derived IP hosts for {}; extra allowlist: {}",
                    self.bind_addr, extra
                )
            }
        }
    }

    /// Check one request.
    ///
    /// [`enforce`] is layered on the whole router by
    /// [`Listener::serve`](crate::transport::Listener::serve), so `/mcp`, an
    /// engine's extra routes and any route added later are covered by
    /// construction. That is deliberate: `ida-headless-mcp` grew a cached-output
    /// endpoint after `/mcp`, and per-route wiring would have made it a second,
    /// unguarded way to read the same tool results.
    ///
    /// **No route is exempt, including a health probe.** An exempt probe is a
    /// free "is an engine running here, and on which port" oracle for anything
    /// on the box, and the only thing it buys is a monitor that does not have to
    /// read a file it can already read.
    ///
    /// **Loopback is not exempt either.** Loopback is not a boundary on a
    /// multi-user machine, and since the default bind *is* loopback, exempting
    /// it would exempt the default.
    ///
    /// Order: Host check first, credential second. Both must pass.
    pub fn validate(
        &self,
        headers: &HeaderMap,
    ) -> Result<(), Box<Response<BoxBody<Bytes, Infallible>>>> {
        self.validate_bearer(headers)?;
        Ok(())
    }

    fn validate_bearer(&self, headers: &HeaderMap) -> Result<(), AccessError> {
        bearer::validate(&self.auth, headers).map_err(|rejection| {
            let mut response = text_response(rejection.status, rejection.message);
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static(rejection.challenge),
            );
            Box::new(response)
        })
    }

    fn validate_host(&self, headers: &HeaderMap) -> Result<(), AccessError> {
        let host = parse_host_header(headers)?;
        if self.host_check_disabled() {
            return Ok(());
        }

        if self.host_allowed_by_bind(&host) || self.allowed_hosts.contains(&host) {
            return Ok(());
        }

        Err(access_error(
            StatusCode::FORBIDDEN,
            format!(
                "Forbidden: Host header '{}' is not allowed; {}",
                host.display(),
                self.host_policy_summary()
            ),
        ))
    }

    fn host_allowed_by_bind(&self, host: &NormalizedAuthority) -> bool {
        if !port_matches(host.port, self.bind_addr.port()) {
            return false;
        }

        let bind_ip = self.bind_addr.ip();
        if host.host == "localhost" {
            return bind_ip.is_loopback() || bind_ip.is_unspecified();
        }

        let Ok(host_ip) = host.host.parse::<IpAddr>() else {
            return false;
        };

        if bind_ip.is_unspecified() {
            return true;
        }
        if bind_ip.is_loopback() {
            return host_ip.is_loopback();
        }
        host_ip == bind_ip
    }
}

/// The axum middleware. Layered on the whole router, never on one route.
pub async fn enforce(
    State(policy): State<AccessPolicy>,
    request: AxumRequest,
    next: Next,
) -> AxumResponse {
    if let Err(response) = policy.validate(request.headers()) {
        let (parts, body) = (*response).into_parts();
        return AxumResponse::from_parts(parts, AxumBody::new(body));
    }
    next.run(request).await
}

fn port_matches(host_port: Option<u16>, bind_port: u16) -> bool {
    match host_port {
        Some(port) => port == bind_port,
        None => true,
    }
}

fn text_response(message_status: StatusCode, message: impl Into<String>) -> AccessResponse {
    let mut response = Response::new(Full::new(Bytes::from(message.into())).boxed());
    *response.status_mut() = message_status;
    response
}

fn access_error(message_status: StatusCode, message: impl Into<String>) -> AccessError {
    Box::new(text_response(message_status, message))
}

fn parse_host_header(headers: &HeaderMap) -> Result<NormalizedAuthority, AccessError> {
    let Some(host) = headers.get(HOST) else {
        return Err(access_error(
            StatusCode::BAD_REQUEST,
            "Bad Request: missing Host header",
        ));
    };
    let host = host
        .to_str()
        .map_err(|_| access_error(StatusCode::BAD_REQUEST, "Bad Request: invalid Host header"))?;
    http::uri::Authority::try_from(host)
        .map(|authority| normalize_authority(authority.host(), authority.port_u16()))
        .map_err(|_| access_error(StatusCode::BAD_REQUEST, "Bad Request: invalid Host header"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HostAllowList {
    Any,
    Restricted(Vec<NormalizedAuthority>),
}

impl HostAllowList {
    fn from_cli(allow_host: Option<&[String]>) -> Self {
        let Some(values) = allow_host else {
            return Self::Restricted(Vec::new());
        };

        let mut hosts = Vec::new();
        for value in values.iter().map(|value| value.trim()) {
            if value == "*" {
                return Self::Any;
            }
            if value.is_empty() {
                continue;
            }
            if let Some(authority) = parse_allowed_authority(value) {
                hosts.push(authority);
            }
        }

        if hosts.is_empty() {
            return Self::Any;
        }
        Self::Restricted(hosts)
    }

    fn contains(&self, host: &NormalizedAuthority) -> bool {
        match self {
            Self::Any => true,
            Self::Restricted(allowed_hosts) => allowed_hosts.iter().any(|allowed| {
                allowed.host == host.host
                    && match allowed.port {
                        Some(port) => host.port == Some(port),
                        None => true,
                    }
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NormalizedAuthority {
    host: String,
    port: Option<u16>,
}

impl NormalizedAuthority {
    fn display(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        }
    }
}

fn normalize_authority(host: &str, port: Option<u16>) -> NormalizedAuthority {
    NormalizedAuthority {
        host: normalize_host(host),
        port,
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase()
}

fn parse_allowed_authority(allowed: &str) -> Option<NormalizedAuthority> {
    let allowed = allowed.trim();
    if allowed.is_empty() {
        return None;
    }

    if let Ok(authority) = http::uri::Authority::try_from(allowed) {
        return Some(normalize_authority(authority.host(), authority.port_u16()));
    }

    Some(normalize_authority(allowed, None))
}

#[cfg(test)]
mod tests {
    use super::AccessPolicy;
    use crate::token::Accepted;
    use http::HeaderMap;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    const TOKEN: &str = "vbr_test_token";

    fn policy(bind: &str, allowed_hosts: Option<&[&str]>) -> AccessPolicy {
        let bind_addr = bind.parse::<SocketAddr>().expect("valid bind address");
        let hosts = allowed_hosts.map(|hosts| {
            hosts
                .iter()
                .map(|host| (*host).to_string())
                .collect::<Vec<_>>()
        });
        let auth = Accepted::new(
            vec![TOKEN.to_string()],
            Some(PathBuf::from("/home/tester/.vibrev/token")),
        )
        .expect("token set");
        AccessPolicy::new(bind_addr, hosts.as_deref(), auth)
    }

    /// Host header plus a valid credential, so the Host assertions below keep
    /// testing Host validation rather than tripping over the bearer gate.
    fn headers(host: &str) -> HeaderMap {
        let mut headers = unauthenticated_headers(host);
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {TOKEN}").parse().expect("valid header"),
        );
        headers
    }

    fn unauthenticated_headers(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, host.parse().expect("valid host"));
        headers
    }

    #[test]
    fn wildcard_bind_allows_lan_ip_literal_hosts() {
        let policy = policy("0.0.0.0:8765", None);
        assert!(policy.validate(&headers("10.10.10.101:8765")).is_ok());
    }

    #[test]
    fn wildcard_bind_allows_lan_ip_even_with_extra_allow_host() {
        let policy = policy("0.0.0.0:8765", Some(&["10.10.10.100"]));
        assert!(policy.validate(&headers("10.10.10.101:8765")).is_ok());
    }

    #[test]
    fn wildcard_bind_rejects_unlisted_dns_host() {
        let policy = policy("0.0.0.0:8765", None);
        let response = policy
            .validate(&headers("example.com:8765"))
            .expect_err("unlisted DNS host should be rejected");
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn explicit_dns_host_allows_matching_host() {
        let policy = policy("0.0.0.0:8765", Some(&["ida-box.local"]));
        assert!(policy.validate(&headers("ida-box.local:8765")).is_ok());
    }

    #[test]
    fn loopback_bind_rejects_lan_ip_literal_host() {
        let policy = policy("127.0.0.1:8765", None);
        let response = policy
            .validate(&headers("10.10.10.101:8765"))
            .expect_err("LAN host should not be valid for loopback bind");
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn wildcard_allow_host_disables_host_check() {
        let policy = policy("127.0.0.1:8765", Some(&["*"]));
        assert!(policy.host_check_disabled());
        assert!(policy.validate(&headers("example.com:9999")).is_ok());
    }

    #[test]
    fn empty_allow_host_disables_host_check() {
        let policy = policy("127.0.0.1:8765", Some(&[""]));
        assert!(policy.host_check_disabled());
        assert!(policy.validate(&headers("example.com:9999")).is_ok());
    }

    #[test]
    fn a_request_without_a_credential_is_401_not_403() {
        let policy = policy("127.0.0.1:8765", None);
        let response = policy
            .validate(&unauthenticated_headers("127.0.0.1:8765"))
            .expect_err("no credential");
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer"),
            "RFC 9110 requires the challenge on a 401"
        );
    }

    #[test]
    fn a_wrong_credential_is_401_with_an_invalid_token_challenge() {
        let policy = policy("127.0.0.1:8765", None);
        let mut headers = unauthenticated_headers("127.0.0.1:8765");
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer vbr_wrong".parse().expect("valid header"),
        );
        let response = policy.validate(&headers).expect_err("wrong credential");
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer error=\"invalid_token\"")
        );
    }

    #[test]
    fn loopback_is_not_exempt_from_the_credential() {
        // The default bind *is* loopback, so a loopback exemption would be an
        // exemption for the default.
        for bind in ["127.0.0.1:8765", "[::1]:8765"] {
            let policy = policy(bind, None);
            assert!(
                policy
                    .validate(&unauthenticated_headers("localhost:8765"))
                    .is_err(),
                "{bind} must still demand a token"
            );
        }
    }

    #[test]
    fn a_valid_credential_passes() {
        let policy = policy("127.0.0.1:8765", None);
        assert!(policy.validate(&headers("127.0.0.1:8765")).is_ok());
    }

    #[test]
    fn origin_is_ignored_when_credential_is_valid() {
        let policy = policy("127.0.0.1:8765", None);
        let mut hostile = headers("127.0.0.1:8765");
        hostile.insert(
            http::header::ORIGIN,
            "http://evil.example".parse().expect("valid header"),
        );
        assert!(policy.validate(&hostile).is_ok());
    }

    #[test]
    fn disabled_host_check_still_requires_host_header() {
        let policy = policy("127.0.0.1:8765", Some(&["*"]));
        let response = policy
            .validate(&HeaderMap::new())
            .expect_err("missing Host remains a bad request");
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }
}
