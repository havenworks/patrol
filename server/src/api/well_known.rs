use super::Resources;
use poem_openapi::{payload::Json, OpenApi};
use serde_json::{json, Value};

pub struct WellKnownApi;

impl WellKnownApi {
    pub const fn root() -> &'static str {
        "/.well-known"
    }
}

#[OpenApi(prefix_path = "/.well-known", tag = "Resources::WellKnown")]
impl WellKnownApi {
    #[oai(path = "/jwks.json", method = "get")]
    async fn jwks_json(&self) -> Json<Value> {
        Json(json!({
            "keys": []
        }))
    }
}
