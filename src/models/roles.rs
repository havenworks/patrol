use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, Object)]
#[sea_orm(table_name = "roles")]
#[oai(rename = "Role")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::users::Entity")]
    User,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        super::users_roles::Relation::User.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::users_roles::Relation::Role.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
