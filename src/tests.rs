// End to end tests against the real router, with real RS256 signed tokens.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;
use tower::ServiceExt; // for oneshot

use crate::config::{Config, PublicKeySource};
use crate::crypto::KeyCipher;
use crate::jwt::TokenVerifier;
use crate::routes::{router, AppState};
use crate::store::KeyStore;

const ISSUER: &str = "https://vault.example.com|login";
const WEB_ORIGIN: &str = "https://vault.example.com";

/// Base64 of a valid 32 byte master key.
fn valid_key() -> String {
    BASE64.encode([0x42u8; 32])
}

/// Base64 of the wrong size (16 bytes).
fn short_key() -> String {
    BASE64.encode([0x42u8; 16])
}

#[derive(Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    nbf: i64,
    exp: i64,
    scope: Vec<String>,
}

fn priv_pem() -> Vec<u8> {
    include_bytes!("../tests/fixtures/test_priv.pem").to_vec()
}

fn pub_pem() -> String {
    include_str!("../tests/fixtures/test_pub.pem").to_string()
}

fn encode_claims<T: Serialize>(claims: &T) -> String {
    let key = EncodingKey::from_rsa_pem(&priv_pem()).unwrap();
    encode(&Header::new(jsonwebtoken::Algorithm::RS256), claims, &key).unwrap()
}

fn sign_scopes(sub: &str, iss: &str, exp_offset: i64, scopes: &[&str]) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = TestClaims {
        sub: sub.to_string(),
        iss: iss.to_string(),
        nbf: now - 10,
        exp: now + exp_offset,
        scope: scopes.iter().map(|s| s.to_string()).collect(),
    };
    encode_claims(&claims)
}

fn sign(sub: &str, iss: &str, exp_offset: i64) -> String {
    sign_scopes(sub, iss, exp_offset, &["api", "offline_access"])
}

fn test_config() -> Config {
    Config {
        bind_addr: "127.0.0.1:0".into(),
        database_url: "sqlite::memory:".into(),
        jwt_issuer: Some(ISSUER.into()),
        public_key: PublicKeySource::Inline(pub_pem()),
        encryption_key: vec![0x42; 32],
        cors_allowed_origins: vec![WEB_ORIGIN.into()],
        api_prefix: String::new(),
    }
}

async fn app_from(cfg: Config) -> axum::Router {
    let verifier = TokenVerifier::from_config(&cfg).await.unwrap();
    let cipher = KeyCipher::new(&cfg.encryption_key).unwrap();
    let store = KeyStore::connect(&cfg.database_url, cipher).await.unwrap();
    router(
        AppState { verifier, store },
        &cfg.cors_allowed_origins,
        &cfg.api_prefix,
    )
}

async fn test_app() -> axum::Router {
    app_from(test_config()).await
}

fn get_request(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(path);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    builder.body(Body::empty()).unwrap()
}

fn post_request(path: &str, token: &str, key: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::json!({ "key": key }).to_string()))
        .unwrap()
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alive_is_unauthenticated() {
    let app = test_app().await;
    let resp = app.oneshot(get_request("/alive", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Round trips and basic auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_then_get_roundtrips_the_key() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, 3600);
    let key = valid_key();

    let resp = app
        .clone()
        .oneshot(post_request("/user-keys", &token, &key))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, format!(r#"{{"key":"{key}"}}"#));
}

#[tokio::test]
async fn get_without_token_is_unauthorized() {
    let app = test_app().await;
    let resp = app.oneshot(get_request("/user-keys", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_issuer_is_rejected() {
    let app = test_app().await;
    let token = sign("user-123", "https://evil.example.com|login", 3600);
    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, -3600); // already expired
    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn users_cannot_read_each_others_keys() {
    let app = test_app().await;
    let alice = sign("alice", ISSUER, 3600);
    let bob = sign("bob", ISSUER, 3600);

    // Alice stores a key.
    app.clone()
        .oneshot(post_request("/user-keys", &alice, &valid_key()))
        .await
        .unwrap();

    // Bob has no key of his own yet -> 404, and never sees Alice's.
    let resp = app
        .oneshot(get_request("/user-keys", Some(&bob)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// JWT hardening: scope + subject validation (no revocation/introspection)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_without_api_scope_is_rejected() {
    let app = test_app().await;
    let token = sign_scopes("user-123", ISSUER, 3600, &["offline_access"]);
    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_with_no_scope_claim_is_rejected() {
    let app = test_app().await;
    let now = chrono::Utc::now().timestamp();
    let token = encode_claims(&serde_json::json!({
        "sub": "user-123",
        "iss": ISSUER,
        "nbf": now - 10,
        "exp": now + 3600,
    }));
    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn space_delimited_scope_is_accepted() {
    let app = test_app().await;
    let now = chrono::Utc::now().timestamp();
    let token = encode_claims(&serde_json::json!({
        "sub": "user-123",
        "iss": ISSUER,
        "nbf": now - 10,
        "exp": now + 3600,
        "scope": "api offline_access",
    }));
    // Authentication succeeds, so this is a 404 (no key stored yet), not a 401.
    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn empty_subject_is_rejected() {
    let app = test_app().await;
    let token = sign("", ISSUER, 3600);
    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn overlong_subject_is_rejected() {
    let app = test_app().await;
    let token = sign(&"x".repeat(300), ISSUER, 3600);
    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_token_response_does_not_leak_details() {
    let app = test_app().await;
    let resp = app
        .oneshot(get_request("/user-keys", Some("not.a.jwt")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_string(resp).await;
    assert_eq!(body, r#"{"message":"invalid access token"}"#);
}

// ---------------------------------------------------------------------------
// Master key validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_rejects_empty_key() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, 3600);
    let resp = app
        .oneshot(post_request("/user-keys", &token, ""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_rejects_invalid_base64_key() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, 3600);
    let resp = app
        .oneshot(post_request("/user-keys", &token, "not base64!!"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_rejects_wrong_length_key() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, 3600);
    let resp = app
        .oneshot(post_request("/user-keys", &token, &short_key()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_accepts_trimmed_valid_key() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, 3600);
    let key = valid_key();
    let padded = format!("  {key}  ");
    let resp = app
        .clone()
        .oneshot(post_request("/user-keys", &token, &padded))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, format!(r#"{{"key":"{key}"}}"#));
}

#[tokio::test]
async fn post_rejects_oversized_body() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, 3600);
    let huge = "A".repeat(9000);
    let resp = app
        .oneshot(post_request("/user-keys", &token, &huge))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn key_response_is_not_cacheable() {
    let app = test_app().await;
    let token = sign("user-123", ISSUER, 3600);
    app.clone()
        .oneshot(post_request("/user-keys", &token, &valid_key()))
        .await
        .unwrap();
    let resp = app
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

fn preflight(origin: &str) -> Request<Body> {
    Request::builder()
        .method("OPTIONS")
        .uri("/user-keys")
        .header("Origin", origin)
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "authorization,bitwarden-client-name,bitwarden-client-version,cache-control,pragma",
        )
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn preflight_from_allowed_origin_gets_cors_headers() {
    let app = test_app().await;
    let resp = app.oneshot(preflight(WEB_ORIGIN)).await.unwrap();
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        WEB_ORIGIN
    );
    // The connector mirrors whatever headers the preflight asks for.
    let allowed = resp
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        allowed.contains("cache-control"),
        "allowed headers: {allowed}"
    );
    assert!(
        allowed.contains("bitwarden-client-name"),
        "allowed headers: {allowed}"
    );
}

#[tokio::test]
async fn preflight_from_disallowed_origin_gets_no_cors_headers() {
    let app = test_app().await;
    let resp = app
        .oneshot(preflight("https://evil.example.com"))
        .await
        .unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn empty_origin_list_denies_cross_origin() {
    let mut cfg = test_config();
    cfg.cors_allowed_origins = vec![];
    let app = app_from(cfg).await;
    let resp = app.oneshot(preflight(WEB_ORIGIN)).await.unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

// ---------------------------------------------------------------------------
// API prefix (deploying under a subpath)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn routes_are_mounted_under_the_api_prefix() {
    let mut cfg = test_config();
    cfg.api_prefix = "/kc".into();
    let app = app_from(cfg).await;
    let token = sign("user-123", ISSUER, 3600);
    let key = valid_key();

    // Unprefixed paths are not served.
    let resp = app
        .clone()
        .oneshot(get_request("/alive", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = app
        .clone()
        .oneshot(get_request("/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Prefixed paths are.
    let resp = app
        .clone()
        .oneshot(get_request("/kc/alive", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(post_request("/kc/user-keys", &token, &key))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .oneshot(get_request("/kc/user-keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, format!(r#"{{"key":"{key}"}}"#));
}

// ---------------------------------------------------------------------------
// Crypto at rest
// ---------------------------------------------------------------------------

#[test]
fn seal_open_roundtrips() {
    let cipher = KeyCipher::new(&[0x42; 32]).unwrap();
    let sealed = cipher.seal("user-123", "AAAABBBBCCCC==").unwrap();
    assert!(KeyCipher::is_sealed(&sealed));
    assert!(!sealed.contains("AAAABBBBCCCC=="));
    assert_eq!(cipher.open("user-123", &sealed).unwrap(), "AAAABBBBCCCC==");
}

#[test]
fn sealed_value_is_bound_to_the_user() {
    let cipher = KeyCipher::new(&[0x42; 32]).unwrap();
    let sealed = cipher.seal("alice", "alice-secret").unwrap();
    assert!(cipher.open("bob", &sealed).is_err());
}

#[test]
fn wrong_key_and_tampering_are_rejected() {
    let cipher = KeyCipher::new(&[0x42; 32]).unwrap();
    let sealed = cipher.seal("user-123", "secret").unwrap();

    let other = KeyCipher::new(&[0x43; 32]).unwrap();
    assert!(other.open("user-123", &sealed).is_err());

    let tampered = format!("{}AA==", &sealed[..sealed.len() - 4]);
    assert!(cipher.open("user-123", &tampered).is_err());
    assert!(cipher.open("user-123", "not-sealed-at-all").is_err());
}

#[test]
fn database_dialect_is_chosen_from_the_url() {
    use crate::store::Dialect;
    assert_eq!(
        Dialect::from_url("mysql://user:pass@db:3306/keyconnector"),
        Dialect::MySql
    );
    assert_eq!(
        Dialect::from_url("sqlite://keyconnector.db?mode=rwc"),
        Dialect::Sqlite
    );
    assert_eq!(Dialect::from_url("sqlite::memory:"), Dialect::Sqlite);
    // The upsert syntax genuinely differs between the two backends.
    assert_ne!(
        Dialect::from_url("mysql://db/kc").upsert(),
        Dialect::from_url("sqlite://kc.db").upsert()
    );
}

#[test]
fn jwk_matches_the_pem_fixture() {
    // n/e of tests/fixtures/test_pub.pem, as Vaultwarden would publish them
    // in its JWKS.
    let jwk = crate::jwt::Jwk {
        kty: "RSA".into(),
        usage: Some("sig".into()),
        n: Some(
            "lcN9Hcvf8PeQUI9y-c7TGdUhyCKfeUSEyPlpMPrkDrRBzkWuu1Nx8qHIu2qvhd81oUD8BEpb10NKnaGtL0Q3bououv6sxxey4esR6WkBxkoLrJBI6rNHR6QBv-_OCm8SbIBsRiS_o5xTzQduN0INonUuceQoS2I__uAN9GH0sBZa9Uj-_PnmyRwIQp_cL15RIcFJIW0vhFhX-t7e0iy3bvsNCGleBwVgTzSO14saLBLQ5o8GdREYGYr-wDjd7gIOiunaXBf1ev-p7u_G5aKUAADAEhVXcTWlUY0NJIQN8enmItEAscWH-sZeJjxFCyZjn7IERYERqCmR4-B6o-cdkQ"
                .into(),
        ),
        e: Some("AQAB".into()),
    };
    let key = crate::jwt::key_from_jwk(&jwk).unwrap();

    // A token signed with the fixture private key verifies against it.
    let token = sign("user-123", ISSUER, 3600);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    let decoded = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation).unwrap();
    assert_eq!(decoded.claims["sub"], "user-123");
}

#[tokio::test]
async fn plaintext_rows_are_sealed_on_startup() {
    // Simulates a database written before encryption at rest existed.
    let db_path = std::env::temp_dir().join(format!("kc-migration-test-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    // sqlx's Any URL parser needs forward slashes, including on Windows.
    let url = format!(
        "sqlite:///{}?mode=rwc",
        db_path.display().to_string().replace('\\', "/")
    );

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE user_keys (user_id TEXT PRIMARY KEY NOT NULL, key TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_keys VALUES ('legacy-user', 'legacy-plaintext-key')")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let store = KeyStore::connect(&url, KeyCipher::new(&[0x42; 32]).unwrap())
        .await
        .unwrap();
    assert_eq!(
        store.get("legacy-user").await.unwrap().unwrap(),
        "legacy-plaintext-key"
    );

    // The row on disk is sealed now.
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect(&url)
        .await
        .unwrap();
    let (stored,): (String,) =
        sqlx::query_as("SELECT key FROM user_keys WHERE user_id = 'legacy-user'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(KeyCipher::is_sealed(&stored));
    assert!(!stored.contains("legacy-plaintext-key"));
    pool.close().await;

    let _ = std::fs::remove_file(&db_path);
}
