use axum::{
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use subtle::ConstantTimeEq;

pub async fn require_basic_auth(expected_password: String, req: Request, next: Next) -> Response {
    if expected_password.is_empty() {
        return next.run(req).await;
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if let Some(auth) = auth_header {
        let trimmed = auth.trim();
        if let Some(token) = trimmed
            .strip_prefix("Basic ")
            .or_else(|| trimmed.strip_prefix("basic "))
        {
            if let Ok(decoded) = base64::prelude::BASE64_STANDARD.decode(token.trim()) {
                if let Ok(cred_str) = String::from_utf8(decoded) {
                    let (_, pass) = cred_str.split_once(':').unwrap_or(("", &cred_str));
                    let pass_match: bool =
                        pass.as_bytes().ct_eq(expected_password.as_bytes()).into();
                    if pass_match {
                        return next.run(req).await;
                    }
                }
            }
        }
    }

    let mut resp = StatusCode::UNAUTHORIZED.into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"gatee\""),
    );
    resp
}
