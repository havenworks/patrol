use crate::models;
use chrono::Utc;
use sea_orm::{entity::prelude::*, Set};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth_token_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub code: String,
    pub redirect_uri: String,

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
