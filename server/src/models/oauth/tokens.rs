use crate::models;
use chrono::{DateTime, Utc};
use sea_orm::{entity::prelude::*, Set};
use serde::{Deserialize, Serialize};

pub const ACCESS_KEY_EXPIRY: i64 = 60 * 24 * 60;
pub const ACCESS_KEY_TYPE: &str = "bearer";
pub const REFRESH_KEY_EXPIRY: i64 = 365 * 24 * 60;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth_tokens")]
pub struct Model {
    #[sea_orm(unique)]
    pub access_key: String,
    pub access_key_created_at: DateTime<Utc>,
    pub access_key_expires_at: DateTime<Utc>,

    #[sea_orm(unique)]
    pub refresh_key: String,
    pub refresh_key_created_at: DateTime<Utc>,
    pub refresh_key_expires_at: DateTime<Utc>,

    // ? Maybe move code to a separate table, because there needs to be more info about it (or keep it here for simplicity)
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub code: String,
    pub code_expiration: DateTime<Utc>,
    pub redirect_uri: String,

    pub client_id: Uuid,
}

#[derive(Debug, Copy, Clone, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "models::clients::Entity",
        from = "Column::ClientId",
        to = "models::clients::Column::Id"
    )]
    Client,
}

impl ActiveModelBehavior for ActiveModel {}
