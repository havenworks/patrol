use anyhow;
use console::{style, Emoji};
use dotenv::dotenv;
use log::info;
use poem::{
    endpoint::EmbeddedFilesEndpoint, error::NotFoundError, listener::TcpListener, EndpointExt,
    Response, Route,
};
use poem_openapi::OpenApiService;
use reqwest::StatusCode;
use rust_embed::RustEmbed;
use sea_orm::DatabaseConnection;
use std::{
    env,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

mod api;
mod db;
// mod keys;
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

#[derive(RustEmbed)]
#[folder = "static"]
#[exclude = "node_modules/*"]
pub struct Static;

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

    let index_html = Static::get("index.html")
        .expect(format!("Could not find {} in `static`", style("index.html").red()).as_str())
        .data
        .to_vec();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in the `.env` file");
    let conn = sea_orm::Database::connect(db_url)
        .await
        .expect("Could not connect to the database");

    info!("{} Running database migrations", Emoji("🗃 ", ""));
    db::run_migrations().await?;

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
                .data(db::is_first_admin_registered(&Db { conn }).await?),
        )
        // Static assets
        .nest("/static", EmbeddedFilesEndpoint::<Static>::new())
        // And then return 'index.html' for unmatched URLs leaving the rest
        // to client-side routing
        .catch_error(move |_: NotFoundError| {
            let index_html_file = index_html.clone();
            async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(index_html_file)
            }
        });

    info!(
        "{} Listening on port {}",
        Emoji("🚀", ""),
        style("8000").bold()
    );
    poem::Server::new(TcpListener::bind(&SocketAddr::from(([127, 0, 0, 1], 8000))))
        .run(app)
        .await?;

    Ok(())
}
