use std::{ops::Deref, str::FromStr};

use crate::{
    api::Resources,
    models::{
        clients::{self, GrantType},
        oauth::tokens::ACCESS_KEY_TYPE,
    },
    models::{
        oauth::token_requests,
        oauth::tokens::{self, ACCESS_KEY_EXPIRY, REFRESH_KEY_EXPIRY},
        users,
    },
    Db,
};

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::debug;
use poem::{
    error::{InternalServerError, Result},
    http::header,
    web::{Data, Path, Query},
    Body, FromRequest, Request,
};
use poem_openapi::{
    param,
    payload::{Json, PlainText, Response},
    ApiExtractor, ApiResponse, Enum, ExtractParamOptions, Object, OpenApi,
};
use rand::distributions::{Alphanumeric, DistString};
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use super::{crypto::hashing, users::verify_password};

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
            GrantType::AuthorizationCode
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
    pub refresh_token: Option<String>,
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
        grant_type: param::Query<String>,
        request: &Request,
        db: Data<&Db>,
    ) -> Result<Response<TokenResponse>> {
        // ! Check grant_type here and return appropriate error message (invalid_grant)

        let token = match GrantType::from_str(&grant_type.to_owned()) {
            Ok(GrantType::AuthorizationCode) => create_token_with_auth_code(&request, &db).await,
            Ok(GrantType::ClientCredentials) => create_token_with_client_creds(&request, &db).await,
            Ok(GrantType::Password) => create_token_with_password(&request, &db).await,
            _ => {
                return Ok(Response::new(TokenResponse::UnsupportedGrantType));
            }
        }?;

        Ok(Response::new(token).header("Cache-Control", "no-cache, no-store"))
    }
}
#[derive(Debug, Deserialize)]
struct TokenAuthCodeParams {
    code: String,
    redirect_uri: String,
    client_id: Uuid,
    client_secret: String,
}

async fn create_token_with_auth_code(request: &Request, db: &Db) -> Result<TokenResponse> {
    let Query(params): Query<TokenAuthCodeParams> = Query::from_request_without_body(request)
        .await
        .map_err(|_| TokenResponse::InvalidRequest)?;

    let redirect_uri = Url::parse(&params.redirect_uri).map_err(|_| TokenResponse::InvalidGrant)?;

    let client = clients::find_by_id(params.client_id)
        .one(&db.conn)
        .await
        .map_err(InternalServerError)?
        .ok_or(TokenResponse::InvalidClient)?;

    // Check if the client secret matches
    if !hashing::verify(
        params.client_secret.as_bytes(),
        &hashing::parse_hash(client.secret.as_str())?,
    ) {
        return Ok(TokenResponse::InvalidClient);
    }

    // Check if the client is allowed to use the grant type
    if !client
        .grant_types
        .contains(&"authorization_code".to_string())
    {
        return Ok(TokenResponse::UnauthorizedClient);
    }

    let token_request = token_requests::Entity::find()
        .filter(token_requests::Column::Code.eq(params.code.clone()))
        .filter(tokens::Column::ClientId.eq(params.client_id.clone()))
        .one(&db.conn)
        .await
        .map_err(InternalServerError)?
        .ok_or(TokenResponse::InvalidGrant)?;

    let authorize_redirect_uri =
        Url::parse(&token_request.redirect_uri).map_err(InternalServerError)?;

    if redirect_uri != authorize_redirect_uri {
        return Ok(TokenResponse::InvalidGrant);
    }

    // ! Implement scope checking
    let scope: Option<String> = None;

    let (access_token, access_token_expires_at) =
        generate_access_token_jwt(&client.id, &token_request.user_id.to_string(), scope)?;
    let (refresh_token, refresh_token_expires_at) = generate_refresh_token();

    tokens::ActiveModel {
        access_key: Set(access_token.clone()),
        access_key_expires_at: Set(access_token_expires_at),

        refresh_key: Set(refresh_token.clone()),
        refresh_key_expires_at: Set(refresh_token_expires_at),

        ..tokens::ActiveModel::new()
    }
    .insert(&db.conn)
    .await
    .map_err(InternalServerError)?;

    let token_response = TokenResponseType {
        access_token,
        refresh_token: Some(refresh_token),
        expires_in: ACCESS_KEY_EXPIRY.to_string(),
        token_type: ACCESS_KEY_TYPE.to_string(),
    };

    return Ok(TokenResponse::Success(Json(token_response)));
}

#[derive(Deserialize)]
struct TokenPasswordParams {
    username: String,
    password: String,
    scope: Option<String>,
    client_id: Uuid,
    client_secret: String,
}

async fn create_token_with_password(request: &Request, db: &Db) -> Result<TokenResponse> {
    let Query(params): Query<TokenPasswordParams> = Query::from_request_without_body(request)
        .await
        .map_err(|_| TokenResponse::InvalidRequest)?;

    let client = clients::find_by_id(params.client_id)
        .one(&db.conn)
        .await
        .map_err(InternalServerError)?
        .ok_or(TokenResponse::InvalidClient)?;

    // Check if the client secret matches
    if !hashing::verify(
        params.client_secret.as_bytes(),
        &hashing::parse_hash(client.secret.as_str())?,
    ) {
        return Ok(TokenResponse::InvalidClient);
    }

    // Check if the client is allowed to use the grant type
    if !client.grant_types.contains(&"password".to_string()) {
        return Ok(TokenResponse::UnauthorizedClient);
    }

    let user = users::find_by_username(params.username)
        .one(&db.conn)
        .await
        .map_err(InternalServerError)?
        .ok_or(TokenResponse::InvalidGrant)?;

    // Check if the client secret matches
    if !hashing::verify(
        params.password.as_bytes(),
        &hashing::parse_hash(&user.password_hash)?,
    ) {
        return Ok(TokenResponse::InvalidClient);
    }

    verify_password(&user, params.password.as_bytes())?.map_err(|_| TokenResponse::InvalidGrant)?;

    // ! Add scopes to Access Token JWT
    // if let Some(scope) = params.scope {
    // }

    let (access_token, access_token_expires_at) =
        generate_access_token_jwt(&client.id, &user.id.to_string(), params.scope)?;
    let (refresh_token, refresh_token_expires_at) = generate_refresh_token();

    tokens::ActiveModel {
        access_key: Set(access_token.clone()),
        access_key_expires_at: Set(access_token_expires_at),

        refresh_key: Set(refresh_token.clone()),
        refresh_key_expires_at: Set(refresh_token_expires_at),

        client_id: Set(client.id),
        user_id: Set(user.id),

        ..tokens::ActiveModel::new()
    }
    .insert(&db.conn)
    .await
    .map_err(InternalServerError)?;

    let token_response = TokenResponseType {
        access_token,
        refresh_token: Some(refresh_token),
        expires_in: ACCESS_KEY_EXPIRY.to_string(),
        token_type: ACCESS_KEY_TYPE.to_string(),
    };

    return Ok(TokenResponse::Success(Json(token_response)));
}

#[derive(Deserialize)]
struct TokenClientCredsParams {
    scope: Option<String>,
    client_id: Uuid,
    client_secret: String,
}

async fn create_token_with_client_creds(request: &Request, db: &Db) -> Result<TokenResponse> {
    let Query(params): Query<TokenClientCredsParams> = Query::from_request_without_body(request)
        .await
        .map_err(|_| TokenResponse::InvalidRequest)?;

    let client = clients::find_by_id(params.client_id)
        .one(&db.conn)
        .await
        .map_err(InternalServerError)?
        .ok_or(TokenResponse::InvalidClient)?;

    // Check if the client secret matches
    if !hashing::verify(
        params.client_secret.as_bytes(),
        &hashing::parse_hash(client.secret.as_str())?,
    ) {
        return Ok(TokenResponse::InvalidClient);
    }

    // Check if the client is allowed to use the grant type
    if !client
        .grant_types
        .contains(&"client_credentials".to_string())
    {
        return Ok(TokenResponse::UnauthorizedClient);
    }

    let (access_token, access_token_expires_at) =
        generate_access_token_jwt(&client.id, &client.id.to_string(), params.scope)?;
    let (refresh_token, refresh_token_expires_at) = generate_refresh_token();

    tokens::ActiveModel {
        access_key: Set(access_token.clone()),
        access_key_expires_at: Set(access_token_expires_at),

        refresh_key: Set(refresh_token.clone()),
        refresh_key_expires_at: Set(refresh_token_expires_at),

        ..tokens::ActiveModel::new()
    }
    .insert(&db.conn)
    .await
    .map_err(InternalServerError)?;

    let token_response = TokenResponseType {
        access_token,
        refresh_token: None,
        expires_in: ACCESS_KEY_EXPIRY.to_string(),
        token_type: ACCESS_KEY_TYPE.to_string(),
    };

    Ok(TokenResponse::Success(Json(token_response)))
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    client_id: String,
    scope: Option<String>,
    jti: String,
    exp: i64,
    iat: i64,
}

fn generate_access_token_jwt(
    client_id: &Uuid,
    sub: &String,
    scope: Option<String>,
) -> Result<(String, DateTime<Utc>)> {
    let mut header = Header::new(Algorithm::RS256);

    header.typ = Some("at+JWT".to_string());

    let now = Utc::now();
    let expires_at = now + Duration::seconds(ACCESS_KEY_EXPIRY);

    let claims = AccessTokenClaims {
        // ! Figure out how to differentiate between instances.
        iss: "patrol".to_string(),
        aud: client_id.to_string(),
        sub: sub.clone(),
        client_id: client_id.to_string(),
        scope,
        jti: Alphanumeric.sample_string(&mut rand::thread_rng(), 32),
        exp: expires_at.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &header,
        &claims,
        // ! Add the secret
        &EncodingKey::from_secret("very_secret_secret".as_bytes()),
    )
    .map_err(InternalServerError)?;

    Ok((token, expires_at))
}

fn generate_refresh_token() -> (String, DateTime<Utc>) {
    let token = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);

    let expires_at = Utc::now() + Duration::seconds(REFRESH_KEY_EXPIRY);

    (token, expires_at)
}
