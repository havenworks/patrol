use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, Object)]
#[sea_orm(table_name = "users_roles")]
#[oai(rename = "User role")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub user_id: Uuid,

    #[sea_orm(primary_key)]
    pub role_name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::roles::Entity",
        from = "Column::RoleName",
        to = "super::roles::Column::Name"
    )]
    Role,
}

impl ActiveModelBehavior for ActiveModel {}
