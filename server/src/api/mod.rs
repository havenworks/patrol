use poem::{session::Session, Request};
use poem_openapi::{auth::ApiKey, SecurityScheme, Tags};

use crate::{
    models::{self, user_tokens, users::Model as User},
    Db,
};

mod clients;
pub mod crypto;
mod error;
mod jwt;
mod oauth;
mod users;
pub mod well_known;

#[derive(Tags)]
pub enum Resources {
    Clients,
    Oauth,
    Users,
    WellKnown,
}

pub const SERVICES: (
    clients::ClientApi,
    oauth::OauthApi,
    users::UserApi,
    well_known::WellKnownApi,
) = (
    clients::ClientApi,
    oauth::OauthApi,
    users::UserApi,
    well_known::WellKnownApi,
);

fn request_db(req: &Request) -> &Db {
    req.data::<&Db>()
        .expect("Could not extract the db pool from the request")
}

fn request_session(request: &Request) -> Option<&Session> {
    request.extensions().get::<Session>()
}

#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    in = "cookie",
    key_name = "patrol_session",
    checker = "auth_logged_in"
)]
pub struct AuthLoggedIn(String);

async fn auth_logged_in(request: &Request, _: ApiKey) -> Option<String> {
    request_session(request)?.get::<String>("token")
}

#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    in = "cookie",
    key_name = "patrol_session",
    checker = "auth_user"
)]
pub struct AuthUser(User);

async fn auth_user(request: &Request, api_key: ApiKey) -> Option<User> {
    let token = auth_logged_in(request, api_key).await?;

    let db = request_db(request);

    user_tokens::find_by_value(token)
        .find_also_related(models::users::Entity)
        .one(&db.conn)
        .await
        .ok()??
        .1
}

#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    in = "cookie",
    key_name = "patrol_session",
    checker = "optional_auth_user"
)]
pub struct OptionalAuthUser(Option<User>);

async fn optional_auth_user(request: &Request, api_key: ApiKey) -> Option<Option<User>> {
    Some(auth_user(request, api_key).await)
}
