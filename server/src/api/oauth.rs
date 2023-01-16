use std::ops::Deref;

use crate::{
    api::Resources,
    models::clients::{self, GrantType},
    Db,
};

use poem::{
    error::{InternalServerError, Result},
    http::header,
    web::{Data, Path},
};
use poem_openapi::{payload::Response, ApiResponse, Enum, OpenApi};
use serde::Deserialize;
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
        

        client.redirect_uris.iter()

        Ok(Response::new(AuthorizeResponse::Redirect).header(header::LOCATION, "/"))
    }
}
