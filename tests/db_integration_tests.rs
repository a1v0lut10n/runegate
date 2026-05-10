// test database integration
use sqlx::{Pool, Postgres};

// sqlx::test automatically provisions a temporary test database, runs the migrations,
// and passes the connected pool to the test function.
#[sqlx::test(migrations = "./migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_database_initialization(pool: Pool<Postgres>) -> sqlx::Result<()> {
    // 1. Create a PgStore instance using the injected pool
    // In actual application code we use PgStore::new() which reads DATABASE_URL.
    // For testing, we can inject the pool if PgStore allows it, or we can use the pool directly to verify schema.
    
    // For now, let's just verify we can query the users table created by migrations
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await?;
        
    assert_eq!(count.0, 0, "Users table should be empty initially");
    
    // Try to insert a dummy user using dynamic query to avoid compile-time DB checks
    sqlx::query("INSERT INTO users (email, is_active) VALUES ($1, $2)")
        .bind("test@example.com")
        .bind(true)
        .execute(&pool)
        .await?;

    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await?;
        
    assert_eq!(count.0, 1, "Users table should have 1 user");

    Ok(())
}
