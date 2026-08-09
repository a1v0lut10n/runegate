use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::env;
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct PgStore {
    pub pool: PgPool,
}

impl PgStore {
    pub async fn new() -> Result<Option<Self>, sqlx::Error> {
        let database_url = match env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                info!("DATABASE_URL is not set. Running without PostgreSQL backend.");
                return Ok(None);
            }
        };

        info!("Connecting to PostgreSQL database...");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;

        info!("Running database migrations...");
        sqlx::migrate!("./migrations").run(&pool).await?;
        info!("Database migrations complete.");

        Ok(Some(Self { pool }))
    }
}

// Data models
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Invite {
    pub id: Uuid,
    pub code: String,
    pub max_uses: i32,
    pub is_revoked: bool,
}

// Identity Store Implementation
impl PgStore {
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT id, email FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn create_user(&self, email: &str) -> Result<User, sqlx::Error> {
        sqlx::query_as::<_, User>("INSERT INTO users (email) VALUES ($1) RETURNING id, email")
            .bind(email)
            .fetch_one(&self.pool)
            .await
    }
}

// Invite Store Implementation
impl PgStore {
    pub async fn get_invite_by_code(&self, code: &str) -> Result<Option<Invite>, sqlx::Error> {
        sqlx::query_as::<_, Invite>(
            "SELECT id, code, max_uses, is_revoked FROM invites WHERE code = $1",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn consume_invite(
        &self,
        invite_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let usage_row =
            sqlx::query("SELECT COUNT(*) as count FROM invite_usages WHERE invite_id = $1")
                .bind(invite_id)
                .fetch_one(&mut *tx)
                .await?;

        let usage_count: i64 = sqlx::Row::try_get(&usage_row, "count").unwrap_or(0);

        let invite_row =
            sqlx::query("SELECT max_uses, is_revoked FROM invites WHERE id = $1 FOR UPDATE")
                .bind(invite_id)
                .fetch_one(&mut *tx)
                .await?;

        let max_uses: i32 = sqlx::Row::try_get(&invite_row, "max_uses")?;
        let is_revoked: bool = sqlx::Row::try_get(&invite_row, "is_revoked")?;

        if is_revoked || usage_count >= max_uses as i64 {
            tx.rollback().await?;
            return Ok(false);
        }

        sqlx::query("INSERT INTO invite_usages (invite_id, user_id) VALUES ($1, $2)")
            .bind(invite_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(true)
    }

    pub async fn create_admin_invite(
        &self,
        code: &str,
        max_uses: i32,
    ) -> Result<Invite, sqlx::Error> {
        sqlx::query_as::<_, Invite>(
            "INSERT INTO invites (code, max_uses) VALUES ($1, $2) RETURNING id, code, max_uses, is_revoked"
        )
        .bind(code)
        .bind(max_uses)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn revoke_invite(&self, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE invites SET is_revoked = true WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// Audit Store Implementation
impl PgStore {
    pub async fn log_audit(
        &self,
        user_id: Option<Uuid>,
        action: &str,
        ip_address: Option<&str>,
        details: Option<serde_json::Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, details) VALUES ($1, $2, $3, $4)",
        )
        .bind(user_id)
        .bind(action)
        .bind(ip_address)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
