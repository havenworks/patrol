use crate::{models::clients, Db};

use super::{crypto, AuthLoggedIn, Resources};
use argon2::password_hash::SaltString;
use poem::{error::InternalServerError, web::Data, Result};
use poem_openapi::{param::Path, payload::Json, ApiResponse, Object, OpenApi};
use rand::distributions::{Alphanumeric, DistString};
use rsa::rand_core::OsRng;
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, EntityTrait, Set};
use uuid::Uuid;

pub struct ClientApi;

#[derive(Object)]
pub struct NewClient {
    name: String,
    homepage_url: Option<String>,
    // logo: Vec<u8>,
    logo_uri: String,

    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
}

#[derive(ApiResponse)]
pub enum CreateClientResponse {
    #[oai(status = 201)]
    Created(Json<ClientCreatedResponse>),
}

#[derive(Object)]
pub struct ClientCreatedResponse {
    client: clients::Model,
    secret: String,
}

#[derive(ApiResponse)]
pub enum ListClientResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<clients::Model>>),
}

#[derive(ApiResponse)]
pub enum DeleteClientResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi(prefix_path = "/api/clients", tag = "Resources::Clients")]
impl ClientApi {
    #[oai(path = "/", method = "post")]
    async fn create(
        &self,
        _token: AuthLoggedIn,
        new_client: Json<NewClient>,
        db: Data<&Db>,
    ) -> Result<CreateClientResponse> {
        let secret = generate_secret();
        let salt = SaltString::generate(&mut OsRng);
        let secret_hash = crypto::hashing::hash(&salt.as_salt(), secret.as_bytes())?.to_string();

        // Create the client in the database
        let client = clients::ActiveModel {
            name: Set(new_client.name.clone()),
            homepage_url: Set(new_client.homepage_url.clone()),
            // logo: Set(new_client.logo.clone()),
            logo: Set(Vec::new()),
            logo_uri: Set(new_client.logo_uri.clone()),

            secret: Set(secret_hash),
            redirect_uris: Set(new_client.redirect_uris.clone()),
            grant_types: Set(new_client.grant_types.clone()),

            ..clients::ActiveModel::new()
        }
        .insert(&db.conn)
        .await
        .map_err(InternalServerError)?;

        Ok(CreateClientResponse::Created(Json(ClientCreatedResponse {
            client,
            secret,
        })))
    }

    #[oai(path = "/clients", method = "get")]
    async fn list(&self, _token: AuthLoggedIn, db: Data<&Db>) -> Result<ListClientResponse> {
        let clients = clients::Entity::find()
            .all(&db.conn)
            .await
            .map_err(InternalServerError)?;

        Ok(ListClientResponse::Ok(Json(clients)))
    }

    #[oai(path = "/clients/{id}", method = "delete")]
    async fn delete(
        &self,
        _token: AuthLoggedIn,
        client_id: Path<Uuid>,
        db: Data<&Db>,
    ) -> Result<DeleteClientResponse> {
        if clients::delete_by_id(*client_id)
            .exec(&db.conn)
            .await
            .map_err(InternalServerError)?
            .rows_affected
            > 0
        {
            Ok(DeleteClientResponse::Deleted)
        } else {
            Ok(DeleteClientResponse::NotFound)
        }
    }
}

fn generate_secret() -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), 64)
}
