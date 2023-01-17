use crate::models;
use chrono::{DateTime, Utc};
use sea_orm::{entity::prelude::*, Set};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub access_key: String,
    pub refresh_key: String,

    pub redirect_uri: String,

    // ? Maybe move code to a separate table, because there needs to be more info about it (or keep it here for simplicity)
    pub code: String,
    pub code_expiration: DateTime<Utc>,

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
