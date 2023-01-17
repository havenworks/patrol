use std::ops::Deref;

use crate::{
    api::Resources,
    models::clients::{self, GrantType},
    models::oauth::tokens,
    Db,
};

use poem::{
    error::{InternalServerError, Result},
    http::header,
    web::{Data, Path},
};
use poem_openapi::{
    payload::{Json, Response},
    ApiResponse, Enum, Object, OpenApi,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

pub struct OauthApi;

#[derive(Copy, Clone, Enum, Deserialize)]
#[oai(rename_all = "snake_case")]
enum ResponseType {
    Code,
    Token,
}

impl ResponseType {
    fn to_grant_type(&self) -> GrantType {
        if let Self::Token = self {
            GrantType::Implicit
        } else {
            GrantType::AuthCode
        }
    }
}

#[derive(ApiResponse)]
enum AuthorizeResponse {
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 428)]
    GrantTypeNotAllowed,
    #[oai(status = 400)]
    InvalidRedirectUri,
    #[oai(status = 303)]
    Redirect,
}

#[derive(ApiResponse)]
enum TokenResponse {
    #[oai(status = 200)]
    Success(Json<TokenResponseType>),
    #[oai(status = 400)]
    InvalidRequest,
    #[oai(status = 401)]
    InvalidClient,
    #[oai(status = 412)]
    InvalidGrant,
    #[oai(status = 403)]
    UnauthorizedClient,
    #[oai(status = 500)]
    UnsupportedGrantType,
    #[oai(status = 403)]
    InvalidScope,
}

#[derive(Object)]
pub struct TokenResponseType {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: String,
}

#[OpenApi(prefix_path = "/oauth", tag = "Resources::Oauth")]
impl OauthApi {
    #[oai(path = "/authorize", method = "get")]
    async fn authorize(
        &self,
        client_id: Path<Uuid>,
        redirect_uri: Path<String>,
        response_type: Path<ResponseType>,
        db: Data<&Db>,
    ) -> Result<Response<AuthorizeResponse>> {
        // Check if the client exists
        let client = clients::find_by_id(*client_id)
            .one(&db.conn)
            .await
            .map_err(InternalServerError)?
            .ok_or(AuthorizeResponse::NotFound)?;

        // Check if the client is allowed to use the grant type
        if !client
            .grant_types
            .contains(&response_type.deref().to_grant_type().to_string())
        {
            return Ok(Response::new(AuthorizeResponse::GrantTypeNotAllowed));
        }

        // Parse the redirect URI and check if it matches any of the URIs
        // registered for the client
        let redirect_uri =
            Url::parse(&redirect_uri).map_err(|_| AuthorizeResponse::InvalidRedirectUri)?;

        // client.redirect_uris.iter()

        Ok(Response::new(AuthorizeResponse::Redirect).header(header::LOCATION, "/"))
    }

    #[oai(path = "/token", method = "post")]
    async fn token(
        &self,
        grant_type: Path<GrantType>,
        code: Path<String>,
        redirect_uri: Path<String>,
        client_id: Path<Uuid>,
        client_secret: Path<String>,
        db: Data<&Db>,
    ) -> Result<Response<TokenResponse>> {
        if *grant_type != GrantType::AuthCode {
            return Ok(Response::new(TokenResponse::InvalidGrant));
        }

        let redirect_uri = Url::parse(&redirect_uri).map_err(|_| TokenResponse::InvalidGrant)?;

        let client = clients::Entity::find()
            .filter(clients::Column::Id.eq(client_id.deref().clone()))
            .filter(clients::Column::Secret.eq(client_secret.deref().clone()))
            .one(&db.conn)
            .await
            .map_err(InternalServerError)?
            .ok_or(TokenResponse::InvalidClient)?;

        if !client.grant_types.contains(&grant_type.deref().to_string()) {
            return Ok(Response::new(TokenResponse::UnauthorizedClient));
        }

        let token = tokens::Entity::find()
            .filter(tokens::Column::Code.eq(code.deref().clone()))
            .filter(tokens::Column::ClientId.eq(client_id.deref().clone()))
            .one(&db.conn)
            .await
            .map_err(InternalServerError)?
            .ok_or(TokenResponse::InvalidGrant)?;

        let authorize_redirect_uri =
            Url::parse(&token.redirect_uri).map_err(InternalServerError)?;

        if redirect_uri != authorize_redirect_uri {
            return Ok(Response::new(TokenResponse::InvalidGrant));
        }

        let token_response = TokenResponseType {
            access_token: "ACC_TOKEN".to_string(),
            refresh_token: "REFRESH_TOKEN".to_string(),
            expires_in: "3600".to_string(),
            token_type: "bearer".to_string(),
        };

        return Ok(Response::new(TokenResponse::Success(Json(token_response)))
            .header("Cache-Control", "no-store"));
    }
}
