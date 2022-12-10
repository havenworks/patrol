use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tokio::process::Command;

use crate::{models::users_roles, Db, FirstAdminRegistered};

pub async fn run_migrations() -> anyhow::Result<()> {
    let status = Command::new("dbmate")
        .arg("migrate")
        .spawn()
        .expect("Cannot run `dbmate`")
        .wait()
        .await?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("`dbmate` exited with a non-zero status code"))
    }
}

pub async fn is_first_admin_registered(db: &Db) -> anyhow::Result<FirstAdminRegistered> {
    let admin = users_roles::Entity::find()
        .filter(users_roles::Column::RoleName.eq("admin"))
        .one(&db.conn)
        .await?;

    Ok(FirstAdminRegistered {
        lock: Arc::new(RwLock::new(admin.is_some())),
    })
}
