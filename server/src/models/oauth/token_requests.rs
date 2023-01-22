use std::str::FromStr;

use crate::models;
use chrono::Utc;
use poem_openapi::Enum;
use sea_orm::{entity::prelude::*, Set};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth_token_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub code: String,
    pub redirect_uri: String,

    pub code_challenge: String,
    pub code_challenge_method: String,

    pub created_at: DateTimeUtc,

    pub client_id: Uuid,
    pub user_id: Uuid,
}

#[derive(Debug, Copy, Clone, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "models::clients::Entity",
        from = "Column::ClientId",
        to = "models::clients::Column::Id"
    )]
    Client,
    #[sea_orm(
        belongs_to = "models::users::Entity",
        from = "Column::UserId",
        to = "models::users::Column::Id"
    )]
    User,
}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        let now = Utc::now();

        Self {
            created_at: Set(now),

            ..ActiveModelTrait::default()
        }
    }
}

pub fn find_by_code<S: Into<String>>(code: S) -> Select<Entity> {
    Entity::find_by_id(code.into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Enum)]
#[oai(rename_all = "snake_case")]
pub enum CodeChallengeMethod {
    Plain,
    S256,
}

impl FromStr for CodeChallengeMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain" => Ok(CodeChallengeMethod::Plain),
            "S256" => Ok(CodeChallengeMethod::S256),
            _ => Err(()),
        }
    }
}

impl ToString for CodeChallengeMethod {
    fn to_string(&self) -> String {
        match self {
            CodeChallengeMethod::Plain => "plain",
            CodeChallengeMethod::S256 => "S256",
        }
        .to_string()
    }
}
