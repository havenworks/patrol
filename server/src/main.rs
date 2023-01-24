use console::{style, Emoji};
use dotenv::dotenv;
use log::info;
use poem::{
    listener::TcpListener,
    session::{CookieConfig, CookieSession},
    web::cookie::CookieKey,
    EndpointExt, Route,
};
use poem_openapi::OpenApiService;
use sea_orm::DatabaseConnection;
use std::{
    env,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

mod api;
mod db;
// mod keys;
mod models;
mod static_files;
// mod util;

#[derive(Clone)]
pub struct Db {
    conn: DatabaseConnection,
}

#[derive(Clone)]
pub struct FirstAdminRegistered {
    lock: Arc<RwLock<bool>>,
}

// 180 days in seconds
const MAX_AGE: u64 = 60 * 60 * 24 * 180;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("{}", style("Application panicked!").bold());

        // Print panic message
        let payload = panic_info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic_info.payload().downcast_ref::<&str>().cloned())
            .unwrap_or("Box<Any>");

        for line in payload.lines() {
            eprintln!("  {}", line);
        }
    }));

    dotenv()?;

    pretty_env_logger::init();

    // Database
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in the `.env` file");
    let conn = sea_orm::Database::connect(db_url)
        .await
        .expect("Could not connect to the database");

    if cfg!(debug_assertions) {
        info!("{}Skipping migrations in development", Emoji("🏃 ", ""));
    } else {
        info!("{}Running database migrations", Emoji("🗃  ", ""));
        db::run_migrations().await?;
    }

    // Cookies
    let cookie_secret =
        env::var("COOKIE_SECRET").expect("COOKIE_SECRET is not set in the `.env` file");
    let cookie_key =
        CookieKey::from(&hex::decode(cookie_secret).expect("Could not decode cookie key"));

    // API
    let service = OpenApiService::new(api::SERVICES, "Patrol", env!("CARGO_PKG_VERSION"))
        .server("https://patrol");

    let ui = service.swagger_ui();
    let spec = service.spec_endpoint();
    let api = service
        .data(Db { conn: conn.clone() })
        .data(db::is_first_admin_registered(&Db { conn }).await?);

    let app = Route::new()
        .nest("/api/swagger", ui)
        .nest("/api/openapi.json", spec)
        .nest_no_strip("/<(api|oauth)>", api)
        .nest("/", static_files::static_routes())
        .with(CookieSession::new(
            CookieConfig::private(cookie_key)
                .name("patrol_session")
                .max_age(Duration::from_secs(MAX_AGE)),
        ));

    info!(
        "{}Listening on port {}",
        Emoji("🚀 ", ""),
        style("8000").bold()
    );
    poem::Server::new(TcpListener::bind(&SocketAddr::from(([127, 0, 0, 1], 8000))))
        .run(app)
        .await?;

    Ok(())
}
