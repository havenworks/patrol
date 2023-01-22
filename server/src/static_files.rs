use poem::{
    endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint, StaticFilesEndpoint},
    http::{header, StatusCode},
    Endpoint, EndpointExt, Response, Route,
};
use rust_embed::RustEmbed;

const APP_DIST_FOLDER: &'static str = "../browser/build/";

#[derive(RustEmbed)]
#[folder = "static"]
#[exclude = "node_modules/*"]
pub struct Static;

pub fn static_routes() -> Route {
    Route::new()
        .nest(
            "/",
            EmbeddedFileEndpoint::<Static>::new("index.html").around(|ep, req| async move {
                if let Some(cookie) = req.cookie().get("_patrol_key") {
                    return Ok(redirect_to("/app"));
                }

                ep.call(req).await
            }),
        )
        .nest("/static", EmbeddedFilesEndpoint::<Static>::new())
        .nest(
            "/app",
            StaticFilesEndpoint::new(APP_DIST_FOLDER)
                .index_file("index.html")
                .fallback_to_index()
                .around(|ep, req| async move {
                    if req.cookie().get("_patrol_key").is_none() {
                        return Ok(redirect_to("/"));
                    }

                    ep.call(req).await
                }),
        )
}

fn redirect_to(path: &str) -> Response {
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, path)
        .finish()
}
