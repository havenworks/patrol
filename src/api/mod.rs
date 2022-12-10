use poem_openapi::{SecurityScheme, Tags};

mod error;
mod jwt;
mod user;
pub mod well_known;

#[derive(Tags)]
pub enum Resources {
    Users,
    WellKnown,
}

pub const SERVICES: (user::UserApi, well_known::WellKnownApi) =
    (user::UserApi, well_known::WellKnownApi);

// #[derive(SecurityScheme)]
// #[oai(
//     type = "api_key",
//     key_name = "authorization",
//     in = "header",
//     checker = ""
// )]
struct AuthUser(super::models::users::Model);

struct AuthAdmin(super::models::users::Model);
