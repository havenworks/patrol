use crate::keys::PatrolRsaKey;
use crate::models::users_roles;
use crate::Db;
use crate::{models::users, FirstAdminRegistered};

use super::error::ApiError;
use super::Resources;

use anyhow::anyhow;
use argon2::password_hash::SaltString;
use argon2::PasswordVerifier;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher},
    Argon2,
};
use chrono::Utc;
use poem::error::InternalServerError;
use poem::web::Data;
use poem::Result;
use poem_openapi::param::Path;
use poem_openapi::{payload::Json, ApiResponse, Enum, Object, OpenApi};
use rsa::padding::PaddingScheme;
use sea_orm::prelude::DateTimeUtc;
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct UserApi;

#[derive(Object)]
struct NewUser {
    #[oai(validator(max_length = 64))]
    username: String,
    // is_admin: bool,
    #[oai(validator(max_length = 32))]
    first_name: String,
    #[oai(validator(max_length = 64))]
    last_name: String,
    #[oai(validator(max_length = 1024))]
    password: String,
}

#[derive(ApiResponse)]
enum CreateUserResponse {
    #[oai(status = 201)]
    Created(Json<users::Model>),
    #[oai(status = 401)]
    Unauthorized(Json<ApiError<String>>),
}

#[derive(Object)]
struct UserLogin {
    #[oai(validator(max_length = 64))]
    username: String,
    #[oai(validator(max_length = 4096))]
    password: String,
}

#[derive(ApiResponse)]
enum LoginResponse {
    #[oai(status = 200)]
    LoggedIn,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 401)]
    Unauthorized(Json<WrongPasswordData>),
}

#[derive(Object)]
struct ChangePassword {
    old_password: String,
    new_password: String,
}

#[derive(ApiResponse)]
enum ChangePasswordResponse {
    #[oai(status = 200)]
    Changed,
    #[oai(status = 401)]
    WrongPassword(Json<ApiError<WrongPasswordData>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(Object, Deserialize)]
struct WrongPasswordData {
    reason: WrongPasswordError,
    #[oai(skip_serializing_if_is_none = true)]
    changed_at: Option<DateTimeUtc>,
}

#[derive(Debug, Enum, Serialize, Deserialize)]
pub enum WrongPasswordError {
    Failed,
    ChangedAt,
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    pub exp: usize,
    pub iss: String,
    pub sub: Uuid,
    pub iat: usize,
    pub jti: Uuid,
}

#[OpenApi(prefix_path = "/api/users", tag = "Resources::Users")]
impl UserApi {
    #[oai(path = "/", method = "post")]
    async fn create(
        &self,
        new_user: Json<NewUser>,
        db: Data<&Db>,
        is_first_admin_registered: Data<&FirstAdminRegistered>,
    ) -> Result<CreateUserResponse> {
        let password_hash = hash_password(new_user.password.as_bytes()).await?;

        // WARN: Not ready for more than a single-instance deployment
        let is_first_admin_registered = &is_first_admin_registered.0.lock;

        // The new user is an admin only if no admin has been registered before
        let is_admin = !*is_first_admin_registered.read().unwrap();

        let txn = db.conn.begin().await.map_err(InternalServerError)?;

        let user: users::Model = users::ActiveModel {
            username: Set(new_user.username.clone()),
            first_name: Set(new_user.first_name.clone()),
            last_name: Set(new_user.last_name.clone()),
            password_hash: Set(password_hash),

            ..users::ActiveModel::new()
        }
        .insert(&txn)
        .await
        .map_err(InternalServerError)?
        .into();

        if is_admin {
            users_roles::ActiveModel {
                user_id: Set(user.id),
                role_name: Set("admin".to_string()),
            }
            .insert(&txn)
            .await
            .map_err(InternalServerError)?;

            *is_first_admin_registered.write().unwrap() = true;
        }

        txn.commit().await.map_err(InternalServerError)?;

        Ok(CreateUserResponse::Created(Json(user)))
    }

    #[oai(path = "/:id/change-password", method = "post")]
    async fn change_password(
        &self,
        user_id: Path<Uuid>,
        change_password: Json<ChangePassword>,
        db: Data<&Db>,
    ) -> Result<ChangePasswordResponse> {
        let user: users::Model = users::find_by_id(*user_id)
            .one(&db.conn)
            .await
            .map_err(InternalServerError)?
            .ok_or(ChangePasswordResponse::NotFound)?;

        // TODO: Michal, finish implementing this, or the   c r a b   will haunt you!
        match verify_password(user.clone(), change_password.old_password.as_bytes())? {
            _ => {}
        }

        let old_password_hash = user.password_hash.clone();

        let new_hash = hash_password(change_password.new_password.as_bytes()).await?;
        let mut active_user: users::ActiveModel = user.into();

        active_user.password_hash_previous = Set(Some(old_password_hash));
        active_user.password_hash = Set(new_hash);
        active_user.password_changed_at = Set(Utc::now());

        active_user
            .update(&db.conn)
            .await
            .map_err(InternalServerError)?;

        Ok(ChangePasswordResponse::NotFound)
    }

    #[oai(path = "/login", method = "post")]
    async fn login(
        &self,
        user_login: Json<UserLogin>,
        private_key: Data<&PatrolRsaKey>,
        db: Data<&Db>,
    ) -> Result<LoginResponse> {
        let user = users::find_by_username(user_login.username.clone())
            .one(&db.conn)
            .await
            .map_err(InternalServerError)?
            .ok_or(LoginResponse::NotFound)?;

        let encrypted_password =
            base64::decode(user_login.password.clone()).map_err(InternalServerError)?;

        let password = (*private_key)
            .0
            .decrypt(PaddingScheme::PKCS1v15Encrypt, &encrypted_password)
            .map_err(InternalServerError)?;

        Ok(match verify_password(user, &password)? {
            Ok(()) => LoginResponse::LoggedIn,
            Err(error) => LoginResponse::Unauthorized(Json(error)),
        })
    }
}

async fn hash_password(password: &[u8]) -> anyhow::Result<String> {
    let salt = SaltString::generate(OsRng);
    let password_hash = Argon2::default()
        .hash_password(password, &salt)
        .map_err(|_| anyhow!("Failed to hash password"))?
        .to_string();

    Ok(password_hash)
}

fn verify_password(
    user: users::Model,
    password: &[u8],
) -> Result<std::result::Result<(), WrongPasswordData>> {
    let hash =
        PasswordHash::new(&user.password_hash).map_err(|_| anyhow!("Failed to parse hash"))?;

    if let Ok(_) = Argon2::default().verify_password(password, &hash) {
        return Ok(Ok(()));
    }

    // If password has been changed
    if let Some(password_hash_previous) = user.password_hash_previous {
        let hash_previous = PasswordHash::new(&password_hash_previous)
            .map_err(|_| anyhow!("Failed to parse hash"))?;

        if let Ok(_) = Argon2::default().verify_password(password, &hash_previous) {
            return Ok(Err(WrongPasswordData {
                reason: WrongPasswordError::ChangedAt,
                changed_at: Some(user.password_changed_at),
            }));
        }
    }

    Ok(Err(WrongPasswordData {
        reason: WrongPasswordError::Failed,
        changed_at: None,
    }))
}
