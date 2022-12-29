use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use console::Emoji;
use log::{info, trace, warn};
use sea_orm::{ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QuerySelect};
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

#[derive(FromQueryResult)]
struct EmptyUser {}

pub async fn is_first_admin_registered(db: &Db) -> anyhow::Result<FirstAdminRegistered> {
    trace!(
        "{}Checking if the first admin is registered",
        Emoji("❓ ", "")
    );

    let admin = users_roles::Entity::find()
        .filter(users_roles::Column::RoleName.eq("admin"))
        .select_only()
        .into_model::<EmptyUser>()
        .one(&db.conn)
        .await?;

    match admin {
        Some(_) => warn!("{}First admin is not registered", Emoji("🧑‍💻 ", "")),
        None => info!("{}First admin is already registered", Emoji("🧑‍💻 ", "")),
    }

    Ok(FirstAdminRegistered {
        lock: Arc::new(RwLock::new(admin.is_some())),
    })
}
