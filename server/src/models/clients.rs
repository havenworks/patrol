use std::str::FromStr;

use chrono::Utc;
use poem_openapi::{Enum, Object};
use sea_orm::{entity::prelude::*, Delete, DeleteMany, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, Object)]
#[sea_orm(table_name = "clients")]
#[oai(rename = "Client")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: Uuid,

    pub name: String,
    pub homepage_url: Option<String>,
    pub logo: Vec<u8>,
    pub logo_uri: String,

    #[sea_orm(unique)]
    pub secret: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,

    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Debug, Copy, Clone, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        let now = Utc::now();

        Self {
            id: Set(Uuid::new_v4()),

            created_at: Set(now),
            updated_at: Set(now),

            ..ActiveModelTrait::default()
        }
    }
}

pub fn find_by_id(id: Uuid) -> Select<Entity> {
    Entity::find_by_id(id)
}

pub fn delete_by_id(id: Uuid) -> DeleteMany<Entity> {
    Entity::delete_by_id(id)
}

// Grant types

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Enum)]
#[oai(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    Password,
    ClientCredentials,
    Implicit,
}

impl ToString for GrantType {
    fn to_string(&self) -> String {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::Password => "password",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::Implicit => "implicit",
        }
        .to_string()
    }
}

impl FromStr for GrantType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "password" => Ok(GrantType::Password),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "implicit" => Ok(GrantType::Implicit),
            _ => Err(()),
        }
    }
}
