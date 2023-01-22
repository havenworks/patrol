use poem::{error::InternalServerError, Request};
use poem_openapi::{auth::ApiKey, SecurityScheme, Tags};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter};

use crate::{models::user_tokens, Db};

use super::models::{self, users::Model as User};

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

#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    in = "cookie",
    key_name = "_patrol_key",
    checker = "auth_user"
)]
struct AuthUser(User);

async fn auth_user(req: &Request, session_id: ApiKey) -> Option<User> {
    let db = req_db_pool(req);

    user_tokens::Entity::find_by_id(session_id.key)
        .filter(user_tokens::Column::Valid.eq(true))
        .one(&db.conn)
        .await
        .ok()
        .flatten()?
        // If a token is found, fetch the user
        .find_related(models::users::Entity)
        .one(&db.conn)
        .await
        .ok()
        .flatten()
}

#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    in = "cookie",
    key_name = "_patrol_key",
    checker = "auth_admin"
)]
struct AuthAdmin(User);

async fn auth_admin(req: &Request, session_id: ApiKey) -> Option<User> {
    let user = auth_user(req, session_id).await?;

    let db = req_db_pool(req);

    models::users_roles::Entity::find_by_id((user.id, "admin".to_string()))
        .one(&db.conn)
        .await
        .ok()?
        .map(|_| user)
}
