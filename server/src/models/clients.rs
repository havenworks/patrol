use chrono::Utc;
use poem_openapi::{Enum, Object};
use sea_orm::{entity::prelude::*, IntoActiveValue, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, DeriveEntityModel, Serialize, Deserialize, Object)]
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

// Grant types

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Enum)]
#[oai(rename_all = "snake_case")]
pub enum GrantType {
    AuthCode,
    Password,
    ClientCreds,
    Implicit,
}

impl ToString for GrantType {
    fn to_string(&self) -> String {
        match self {
            GrantType::AuthCode => "authorization_code",
            GrantType::Password => todo!(),
            GrantType::ClientCreds => todo!(),
            GrantType::Implicit => todo!(),
        }
        .to_string()
    }
}
