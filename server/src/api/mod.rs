use poem::{error::InternalServerError, session::Session, Request};
use poem_openapi::{auth::ApiKey, SecurityScheme, Tags};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter};

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

fn req_db_pool(req: &Request) -> &Db {
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
pub struct AuthLoggedIn(());

async fn auth_logged_in(request: &Request, _: ApiKey) -> Option<()> {
    request_session(request)?.get::<String>("token").map(|_| ())
}

#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    in = "cookie",
    key_name = "patrol_session",
    checker = "auth_user"
)]
pub struct AuthUser(Option<User>);

async fn auth_user(request: &Request, _: ApiKey) -> Option<Option<User>> {
    let token = match request_session(request)?.get::<String>("token") {
        Some(token) => token,
        None => return Some(None),
    };

    let db = req_db_pool(request);

    let user = user_tokens::find_by_value(token)
        .find_also_related(models::users::Entity)
        .one(&db.conn)
        .await
        .ok()??
        .1;

    Some(user)
}
