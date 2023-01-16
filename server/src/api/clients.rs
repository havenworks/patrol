use crate::{models::clients, Db};

use super::{crypto, AuthAdmin};
use poem::{error::InternalServerError, web::Data, Result};
use poem_openapi::{payload::Json, ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, Set};

pub struct ClientApi;

#[derive(Object)]
pub struct NewClient {
    name: String,
    homepage_url: Option<String>,
    logo: Vec<u8>,
    logo_uri: String,

    secret: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
}

#[derive(ApiResponse)]
pub enum CreateClientResponse {
    #[oai(status = 201)]
    Created(Json<clients::Model>),
}

#[OpenApi(prefix_path = "/api/clients", tag = "Resources::Clients")]
impl ClientApi {
    async fn create(
        &self,
        _admin: AuthAdmin,
        new_client: Json<NewClient>,
        db: Data<&Db>,
    ) -> Result<CreateClientResponse> {
        let secret_hash = crypto::hashing::hash(new_client.secret.as_bytes())?
            .0
            .to_string();

        // Create the client in the database
        let client = clients::ActiveModel {
            name: Set(new_client.name.clone()),
            homepage_url: Set(new_client.homepage_url.clone()),
            logo: Set(new_client.logo.clone()),
            logo_uri: Set(new_client.logo_uri.clone()),

            secret: Set(secret_hash),
            redirect_uris: Set(new_client.redirect_uris.clone()),
            grant_types: Set(new_client.grant_types.clone()),

            ..clients::ActiveModel::new()
        }
        .insert(&db.conn)
        .await
        .map_err(InternalServerError)?;

        Ok(CreateClientResponse::Created(Json(client)))
    }
}
