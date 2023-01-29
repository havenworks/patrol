use chrono::Utc;
use poem_openapi::Object;
use sea_orm::{entity::prelude::*, Set};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, Object)]
#[sea_orm(table_name = "user_emails")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: Uuid,

    #[sea_orm(unique)]
    pub email: String,
    pub verified_at: Option<DateTimeUtc>,

    pub user_id: Uuid,

    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id"
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
        let now = Utc::now();

        Self {
            verified_at: Set(None),

            created_at: Set(now),
            updated_at: Set(now),

            ..ActiveModelTrait::default()
        }
    }
}
