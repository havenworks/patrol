use chrono::Utc;
use poem_openapi::Object;
use sea_orm::{entity::prelude::*, Select, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, Object)]
#[sea_orm(table_name = "users")]
#[oai(rename = "User")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: Uuid,

    #[sea_orm(unique)]
    pub username: String,

    pub first_name: String,
    pub last_name: String,

    pub profile_picture: Option<String>,

    #[serde(skip_serializing)]
    pub password_hash: String,
    #[serde(skip_serializing)]
    pub password_hash_previous: Option<String>,
    #[serde(skip_serializing)]
    pub password_changed_at: DateTimeUtc,

    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::roles::Entity")]
    Role,
}

impl Related<super::roles::Entity> for Entity {
    fn to() -> RelationDef {
        super::users_roles::Relation::Role.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::users_roles::Relation::User.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        let now = Utc::now();

        Self {
            id: Set(Uuid::new_v4()),

            profile_picture: Set(None),

            password_hash_previous: Set(None),
            password_changed_at: Set(now),

            created_at: Set(now),
            updated_at: Set(now),

            ..ActiveModelTrait::default()
        }
    }
}

pub fn find_by_id(id: Uuid) -> Select<Entity> {
    Entity::find_by_id(id)
}

pub fn find_by_username(username: String) -> Select<Entity> {
    Entity::find().filter(Column::Username.eq(username))
}
