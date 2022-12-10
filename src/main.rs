use anyhow;
use dotenv::dotenv;
use poem::{listener::TcpListener, EndpointExt, Route};
use poem_openapi::OpenApiService;
use sea_orm::DatabaseConnection;
use std::{
    env,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

mod api;
mod db;
mod keys;
mod models;
// mod util;

#[derive(Clone)]
pub struct Db {
    conn: DatabaseConnection,
}

#[derive(Clone)]
pub struct FirstAdminRegistered {
    lock: Arc<RwLock<bool>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv()?;

    pretty_env_logger::init();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let conn = sea_orm::Database::connect(db_url)
        .await
        .expect("Could not connect to the database");

    db::run_migrations().await?;

    let (jwks, jwks_value) = keys::generate_keys();

    let service = OpenApiService::new(api::SERVICES, "Patrol", env!("CARGO_PKG_VERSION"))
        .server("https://patrol");

    let ui = service.swagger_ui();
    let spec = service.spec_endpoint();
    let app = Route::new()
        .nest("/api/swagger", ui)
        .nest("/api/openapi.json", spec)
        .nest(
            "/",
            service
                .data(Db { conn: conn.clone() })
                .data(db::is_first_admin_registered(&Db { conn }).await?)
                .data(jwks)
                .data(jwks_value),
        );

    poem::Server::new(TcpListener::bind(&SocketAddr::from(([127, 0, 0, 1], 8000))))
        .run(app)
        .await?;

    Ok(())
}
