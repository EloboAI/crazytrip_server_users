use tokio_postgres::NoTls;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connection to the 'postgres' default database to manage databases
    let conn_str = "host=127.0.0.1 user=postgres password=moti dbname=postgres";

    println!("Connecting to Postgres at 127.0.0.1:5432 as user 'postgres'...");

    let (client, connection) = tokio_postgres::connect(conn_str, NoTls).await?;

    // Spawn connection processing
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    // Check if database exists
    let db_name = "crazytrip_users";
    let row = client
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&db_name])
        .await?;

    if row.is_some() {
        println!("Database '{}' already exists.", db_name);
        return Ok(());
    }

    // Create database
    // Validate database name to avoid SQL injection via identifier
    // Allow only alphanumeric and underscore characters
    let valid_name = db_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_');

    if !valid_name {
        eprintln!(
            "Refusing to create database: invalid database name '{}'.",
            db_name
        );
        return Ok(());
    }

    let create_sql = format!("CREATE DATABASE \"{}\"", db_name);
    match client.execute(create_sql.as_str(), &[]).await {
        Ok(_) => println!("Database '{}' created successfully.", db_name),
        Err(e) => eprintln!("Failed to create database '{}': {}", db_name, e),
    }

    Ok(())
}
