use std::{ops::Deref, str::FromStr};

use crate::{
    api::{auth_user, request_session, try_me_bitch, Resources},
    models::{
        clients::{self, GrantType},
        oauth::{
            token_requests::{self, CodeChallengeMethod},
            tokens::{self, ACCESS_KEY_EXPIRY, ACCESS_KEY_TYPE, REFRESH_KEY_EXPIRY},
        },
        users,
    },
    Db,
};

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use poem::{
    error::{InternalServerError, Result},
    http::header,
    web::{self, Data, Path},
    FromRequest, Request,
};
use poem_openapi::{
    auth::ApiKey,
    param::Query,
    payload::{Json, Response},
    ApiResponse, Enum, Object, OpenApi,
};
use rand::distributions::{Alphanumeric, DistString};
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, ColumnTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use super::{crypto::hashing, users::verify_password, OptionalAuthUser};

pub struct OauthApi;

#[derive(Copy, Clone, Enum, Deserialize, PartialEq)]
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

#[derive(Object)]
struct ImplicitGrantResponse {
    access_token: String,
    token_type: String,
    expires_in: String,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(ApiResponse)]
enum AuthorizeResponse {
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 428)]
    GrantTypeNotAllowed,
    #[oai(status = 400)]
    InvalidRedirectUri,
    #[oai(status = 307)]
    Redirect,
    #[oai(status = 200)]
    Token(Json<ImplicitGrantResponse>),
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
        response_type: Query<ResponseType>,
        client_id: Query<Uuid>,
        redirect_uri: Query<String>,
        scope: Query<Option<String>>,
        state: Query<Option<String>>,
        code_challenge: Query<String>,
        code_challenge_method: Query<Option<String>>,
        request: &Request,
        db: Data<&Db>,
    ) -> Result<Response<AuthorizeResponse>> {
        // localhost:8000/oauth/authorize?response_type=code&client_id=dbe3cb01-6b60-4a19-a60c-5629a48d9ec5&redirect_uri=http://localhost:1234/oauth/callback&code_challenge=ahojda

        // ! Used for development until @michaljanocko fixes the SecurityScheme bullshit.
        let user: Option<users::Model> = try_me_bitch(request, &db).await;

        // Parse the redirect URI and check if it matches any of the URIs
        // registered for the client
        let mut redirect_uri =
            Url::parse(&redirect_uri).map_err(|_| AuthorizeResponse::InvalidRedirectUri)?;

        // Check if the client exists
        let client = clients::find_by_id(*client_id)
            .one(&db.conn)
            .await
            .map_err(InternalServerError)?
            .ok_or(AuthorizeResponse::NotFound)?;

        if !client.redirect_uris.iter().any(|uri| {
            let uri = Url::parse(uri).unwrap();
            redirect_uri == uri
        }) {
            return Ok(Response::new(AuthorizeResponse::InvalidRedirectUri));
        }

        // Check if the client is allowed to use the grant type
        if !client
            .grant_types
            .contains(&response_type.deref().to_grant_type().to_string())
        {
            return Ok(Response::new(AuthorizeResponse::GrantTypeNotAllowed));
        }

        let user = match user {
            None => {
                let mut login_page = Url::parse("http://localhost:8000").unwrap();
                login_page
                    .query_pairs_mut()
                    .append_pair("client_id", client.id.to_string().as_str())
                    .append_pair("return_to", request.original_uri().to_string().as_str());

                return Ok(Response::new(AuthorizeResponse::Redirect)
                    .header(header::LOCATION, login_page.to_string()));
            }
            Some(user) => user,
        };

        if *response_type == ResponseType::Token {
            let (access_token, access_token_expires_at) =
                generate_access_token_jwt(&client.id, &user.id.to_string(), scope.clone())?;

            tokens::ActiveModel {
                access_key: Set(access_token.clone()),
                access_key_expires_at: Set(access_token_expires_at),

                refresh_key: Set(None),
                refresh_key_expires_at: Set(None),

                client_id: Set(client.id),
                user_id: Set(Some(user.id)),

                ..tokens::ActiveModel::new()
            }
            .insert(&db.conn)
            .await
            .map_err(InternalServerError)?;

            let response = ImplicitGrantResponse {
                access_token,
                expires_in: ACCESS_KEY_EXPIRY.to_string(),
                token_type: ACCESS_KEY_TYPE.to_string(),
                scope: scope.clone(),
                state: state.clone(),
            };

            return Ok(Response::new(AuthorizeResponse::Token(Json(response)))
                .header("cache-control", "no-store, no-cache"));
        }

        let code_challenge_method = CodeChallengeMethod::from_str(
            (*code_challenge_method)
                .clone()
                .unwrap_or("plain".to_string())
                .as_str(),
        )
        .map_err(|_| TokenResponse::InvalidRequest)?;

        let code = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);

        token_requests::ActiveModel {
            code: Set(code.clone()),
            redirect_uri: Set(redirect_uri.to_string()),

            code_challenge: Set(code_challenge.clone()),
            code_challenge_method: Set(code_challenge_method.to_string()),

            client_id: Set(client.id.clone()),
            user_id: Set(user.id.clone()),

            ..token_requests::ActiveModel::new()
        }
        .insert(&db.conn)
        .await
        .map_err(InternalServerError)?;

        redirect_uri
            .query_pairs_mut()
            .append_pair("code", code.as_str());

        if let Some(state) = state.deref() {
            redirect_uri
                .query_pairs_mut()
                .append_pair("state", state.as_str());
        }

        Ok(Response::new(AuthorizeResponse::Redirect)
            .header(header::LOCATION, redirect_uri.to_string()))
    }

    #[oai(path = "/token", method = "post")]
    async fn token(
        &self,
        grant_type: Query<String>,
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
    code_verifier: String,
}

async fn create_token_with_auth_code(request: &Request, db: &Db) -> Result<TokenResponse> {
    let web::Query(params): web::Query<TokenAuthCodeParams> =
        web::Query::from_request_without_body(request)
            .await
            .map_err(|_| TokenResponse::InvalidRequest)?;

    let redirect_uri = Url::parse(&params.redirect_uri).map_err(|_| TokenResponse::InvalidGrant)?;

    let client = match find_matching_client(
        params.client_id,
        params.client_secret,
        "authorization_code",
        &db,
    )
    .await?
    {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };

    let token_request = token_requests::find_by_code(params.code)
        .filter(tokens::Column::ClientId.eq(params.client_id.clone()))
        .one(&db.conn)
        .await
        .map_err(InternalServerError)?
        .ok_or(TokenResponse::InvalidGrant)?;

    let code_challenge_method =
        CodeChallengeMethod::from_str(token_request.code_challenge_method.as_str())
            .map_err(|_| TokenResponse::InvalidRequest)?;

    let challenge_successful = match code_challenge_method {
        CodeChallengeMethod::Plain => token_request.code_challenge == params.code_verifier,
        CodeChallengeMethod::S256 => {
            let mut hasher = Sha256::new();
            hasher.update(params.code_verifier.as_bytes());
            let hashed_code_verifier = hasher.finalize();

            let encoded_code_verifier = base64_url::encode(hashed_code_verifier.as_slice());

            token_request.code_challenge == encoded_code_verifier
        }
    };

    if !challenge_successful {
        return Ok(TokenResponse::InvalidGrant);
    }

    let authorize_redirect_uri =
        Url::parse(&token_request.redirect_uri).map_err(InternalServerError)?;

    if redirect_uri != authorize_redirect_uri {
        return Ok(TokenResponse::InvalidGrant);
    }

    // TODO: Implement scope checking
    let scope: Option<String> = None;

    let (access_token, access_token_expires_at) =
        generate_access_token_jwt(&client.id, &token_request.user_id.to_string(), scope)?;
    let (refresh_token, refresh_token_expires_at) = generate_refresh_token();

    tokens::ActiveModel {
        access_key: Set(access_token.clone()),
        access_key_expires_at: Set(access_token_expires_at),

        refresh_key: Set(Some(refresh_token.clone())),
        refresh_key_expires_at: Set(Some(refresh_token_expires_at)),

        client_id: Set(client.id),
        user_id: Set(Some(token_request.user_id)),

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
    let web::Query(params): web::Query<TokenPasswordParams> =
        web::Query::from_request_without_body(request)
            .await
            .map_err(|_| TokenResponse::InvalidRequest)?;

    let client = match find_matching_client(params.client_id, params.client_secret, "password", &db)
        .await?
    {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };

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

        refresh_key: Set(Some(refresh_token.clone())),
        refresh_key_expires_at: Set(Some(refresh_token_expires_at)),

        client_id: Set(client.id),
        user_id: Set(Some(user.id)),

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
    let web::Query(params): web::Query<TokenClientCredsParams> =
        web::Query::from_request_without_body(request)
            .await
            .map_err(|_| TokenResponse::InvalidRequest)?;

    let client = match find_matching_client(
        params.client_id,
        params.client_secret,
        "client_credentials",
        &db,
    )
    .await?
    {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };

    let (access_token, access_token_expires_at) =
        generate_access_token_jwt(&client.id, &client.id.to_string(), params.scope)?;
    let (refresh_token, refresh_token_expires_at) = generate_refresh_token();

    tokens::ActiveModel {
        access_key: Set(access_token.clone()),
        access_key_expires_at: Set(access_token_expires_at),

        refresh_key: Set(Some(refresh_token.clone())),
        refresh_key_expires_at: Set(Some(refresh_token_expires_at)),

        client_id: Set(client.id),
        user_id: Set(None),

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

async fn find_matching_client(
    client_id: Uuid,
    client_secret: String,
    grant_type: &str,
    db: &Db,
) -> Result<std::result::Result<clients::Model, TokenResponse>> {
    let client = clients::find_by_id(client_id)
        .one(&db.conn)
        .await
        .map_err(InternalServerError)?
        .ok_or(TokenResponse::InvalidClient)?;

    // Check if the client secret matches
    if !hashing::verify(
        client_secret.as_bytes(),
        &hashing::parse_hash(client.secret.as_str())?,
    ) {
        return Ok(Err(TokenResponse::InvalidClient));
    }

    // Check if the client is allowed to use the grant type
    if !client.grant_types.contains(&grant_type.to_string()) {
        return Ok(Err(TokenResponse::UnauthorizedClient));
    }

    Ok(Ok(client))
}
