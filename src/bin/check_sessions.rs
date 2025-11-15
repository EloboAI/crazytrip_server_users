use tokio_postgres::NoTls;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn_str = "host=127.0.0.1 user=postgres password=moti dbname=crazytrip_users";
    println!("Connecting to crazytrip_users...");
    let (mut client, connection) = tokio_postgres::connect(conn_str, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    // Check table existence via information_schema
    let row = client.query_one("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'sessions')", &[]).await?;
    let exists: bool = row.get(0);
    println!("sessions table exists = {}", exists);

    if !exists {
        println!("sessions table does not exist");
        return Ok(());
    }

    // Count rows
    let row = client.query_one("SELECT COUNT(*) FROM sessions", &[]).await?;
    let count: i64 = row.get(0);
    println!("sessions rows: {}", count);

    // Try delete inside transaction and rollback to capture any error
    let tx = client.transaction().await?;
    match tx.execute("DELETE FROM sessions WHERE expires_at < NOW() RETURNING id", &[]).await {
        Ok(rows) => println!("DELETE returned {} rows (in tx)", rows),
        Err(e) => eprintln!("DELETE error: {}", e),
    }
    tx.rollback().await?;

    Ok(())
}
