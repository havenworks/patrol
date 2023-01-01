use poem::Request;
use poem_openapi::{auth::ApiKey, SecurityScheme, Tags};
use sea_orm::EntityTrait;

use crate::Db;

use super::models::{self, users::Model as User};

mod error;
mod jwt;
mod oauth;
mod users;
pub mod well_known;

#[derive(Tags)]
pub enum Resources {
    Oauth,
    Users,
    WellKnown,
}

pub const SERVICES: (users::UserApi, well_known::WellKnownApi) =
    (users::UserApi, well_known::WellKnownApi);

fn req_db_pool(req: &Request) -> &Db {
    req.data::<&Db>()
        .expect("Could not extract the db pool from the request")
}

#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    key_name = "session",
    in = "cookie",
    checker = "auth_user"
)]
struct AuthUser(User);

async fn auth_user(req: &Request, session_id: ApiKey) -> Option<User> {
    let db = req_db_pool(req);
    None
}

#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    key_name = "session",
    in = "cookie",
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
