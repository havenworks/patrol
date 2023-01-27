use console::{style, Emoji};
use dotenv::dotenv;
use log::info;
use poem::{
    endpoint::{EmbeddedFilesEndpoint, StaticFilesEndpoint},
    error::NotFoundError,
    http::header,
    listener::TcpListener,
    middleware::CookieJarManager,
    session::{CookieConfig, CookieSession},
    web::cookie::CookieKey,
    Endpoint, EndpointExt, Request, Response, Route,
};
use poem_openapi::OpenApiService;
use reqwest::StatusCode;
use rust_embed::RustEmbed;
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

    // let index_html = Static::get("index.html")
    //     .unwrap_or_else(|| panic!("Could not find {} in `static`", style("index.html").red()))
    //     .data
    //     .to_vec();

    // Database
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in the `.env` file");
    let conn = sea_orm::Database::connect(db_url)
        .await
        .expect("Could not connect to the database");

    info!("{} Running database migrations", Emoji("🗃 ", ""));
    db::run_migrations().await?;

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
    let app = Route::new()
        .nest("/api/swagger", ui)
        .nest("/api/openapi.json", spec)
        .nest_no_strip(
            "/<(api|oauth)>",
            service.data(db::is_first_admin_registered(&Db { conn: conn.clone() }).await?),
        )
        .nest("/", static_files::static_routes())
        .data(Db { conn: conn.clone() })
        .with(CookieSession::new(
            CookieConfig::default()
                .name("patrol_session")
                .max_age(Duration::from_secs(MAX_AGE)),
        ));

    // And then return 'index.html' for unmatched URLs leaving the rest
    // to client-side routing
    // .catch_error(move |_: NotFoundError| {
    //     let index_html_file = index_html.clone();
    //     async move {
    //         Response::builder()
    //             .status(StatusCode::OK)
    //             .body(index_html_file)
    //     }
    // });

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
