use crate::models;
use sea_orm::{entity::prelude::*, DeleteMany, Set};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub value: String,
    pub valid: bool,

    pub user_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "models::users::Entity",
        from = "Column::UserId",
        to = "models::users::Column::Id"
    )]
    User,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        Self {
            valid: Set(true),

            ..ActiveModelTrait::default()
        }
    }
}

pub fn find_by_value<S: Into<String>>(value: S) -> Select<Entity> {
    Entity::find_by_id(value.into())
}

pub fn delete_by_value<S: Into<String>>(value: S) -> DeleteMany<Entity> {
    Entity::delete_by_id(value.into())
}
