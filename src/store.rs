use std::sync::Once;

use sqlx::any::{install_default_drivers, AnyPoolOptions};
use sqlx::AnyPool;

use crate::crypto::KeyCipher;

/// Which SQL dialect the configured database speaks. Detected from the URL
/// scheme; only the schema and upsert syntax actually differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    MySql,
}

impl Dialect {
    pub fn from_url(database_url: &str) -> Self {
        if database_url.starts_with("mysql:") {
            Dialect::MySql
        } else {
            Dialect::Sqlite
        }
    }

    /// SQLite supports ON CONFLICT ... DO UPDATE, MySQL uses ON DUPLICATE KEY
    /// UPDATE. Both use ? placeholders under sqlx's Any driver.
    pub fn upsert(self) -> &'static str {
        match self {
            Dialect::Sqlite => "INSERT INTO user_keys (user_id, `key`) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET `key` = excluded.`key`",
            Dialect::MySql => "INSERT INTO user_keys (user_id, `key`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `key` = VALUES(`key`)",
        }
    }
}

// Maps the user id (JWT sub) to the stored key blob. The value is sealed at
// rest and returned verbatim to the client, it is never parsed or used.
#[derive(Clone)]
pub struct KeyStore {
    pool: AnyPool,
    cipher: KeyCipher,
    dialect: Dialect,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl KeyStore {
    pub async fn connect(database_url: &str, cipher: KeyCipher) -> Result<Self, StoreError> {
        install_drivers();

        let dialect = Dialect::from_url(database_url);
        // An in-memory SQLite database is private to a single connection, so a
        // pool with more than one connection would see different empty
        // databases. Files and MySQL servers do not have that problem.
        let max_connections = if database_url.contains(":memory:") {
            1
        } else {
            5
        };
        let pool = AnyPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;

        // "key" is a reserved word in MySQL, so it is quoted everywhere.
        // VARCHAR is used for both columns because MySQL reports TEXT as BLOB,
        // which sqlx's Any driver refuses to decode back into a String.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_keys (
                user_id VARCHAR(255) PRIMARY KEY NOT NULL,
                `key`   VARCHAR(1024) NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        let store = Self {
            pool,
            cipher,
            dialect,
        };
        store.seal_plaintext_rows().await?;
        Ok(store)
    }

    // Rows written before encryption at rest existed are plaintext. Seal them
    // once at startup; the table holds one row per SSO user, so a full scan
    // is cheap.
    async fn seal_plaintext_rows(&self) -> Result<(), StoreError> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT user_id, `key` FROM user_keys")
            .fetch_all(&self.pool)
            .await?;

        let mut sealed_count = 0;
        for (user_id, key) in rows {
            if KeyCipher::is_sealed(&key) {
                continue;
            }
            let sealed = self
                .cipher
                .seal(&user_id, &key)
                .map_err(StoreError::Crypto)?;
            sqlx::query("UPDATE user_keys SET `key` = ? WHERE user_id = ?")
                .bind(sealed)
                .bind(user_id)
                .execute(&self.pool)
                .await?;
            sealed_count += 1;
        }
        if sealed_count > 0 {
            tracing::info!(count = sealed_count, "sealed plaintext key rows");
        }
        Ok(())
    }

    pub async fn get(&self, user_id: &str) -> Result<Option<String>, StoreError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT `key` FROM user_keys WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        match row {
            None => Ok(None),
            Some((stored,)) => {
                let key = self
                    .cipher
                    .open(user_id, &stored)
                    .map_err(StoreError::Crypto)?;
                Ok(Some(key))
            }
        }
    }

    pub async fn set(&self, user_id: &str, key: &str) -> Result<(), StoreError> {
        let sealed = self.cipher.seal(user_id, key).map_err(StoreError::Crypto)?;
        sqlx::query(self.dialect.upsert())
            .bind(user_id)
            .bind(sealed)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// sqlx's Any driver needs its backend drivers registered once per process.
fn install_drivers() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(install_default_drivers);
}
