use crate::models;
use chrono::Utc;
use sea_orm::{entity::prelude::*, Set};
use serde::{Deserialize, Serialize};

pub const ACCESS_KEY_EXPIRY: i64 = 60 * 24 * 60;
pub const ACCESS_KEY_TYPE: &str = "bearer";
pub const REFRESH_KEY_EXPIRY: i64 = 365 * 24 * 60;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub access_key: String,
    pub access_key_expires_at: DateTimeUtc,

    #[sea_orm(unique)]
    pub refresh_key: String,
    pub refresh_key_expires_at: DateTimeUtc,

    pub client_id: Uuid,
    pub user_id: Uuid,

    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
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
            updated_at: Set(now),

            ..ActiveModelTrait::default()
        }
    }
}
