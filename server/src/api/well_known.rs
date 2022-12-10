use crate::keys::PatrolJwkSetValue;

use super::Resources;
use poem::web::Data;
use poem_openapi::{
    payload::{Json, Response},
    OpenApi,
};
use serde_json::Value;

pub struct WellKnownApi;

#[OpenApi(prefix_path = "/.well-known", tag = "Resources::WellKnown")]
impl WellKnownApi {
    #[oai(path = "/jwks.json", method = "get")]
    async fn jwks_json(&self, jwks: Data<&PatrolJwkSetValue>) -> Response<Json<Value>> {
        Response::new(Json((*jwks).0.clone()))
    }
}
