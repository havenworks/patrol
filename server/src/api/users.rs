use std::time::Duration;

use crate::models::{user_tokens, users_roles};
use crate::{models::users, FirstAdminRegistered};
use crate::{Db, MAX_AGE};

use super::crypto;
use super::error::ApiError;
use super::{AuthAdmin, AuthUser, Resources};

use anyhow::anyhow;
use argon2::password_hash::SaltString;
use argon2::PasswordVerifier;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher},
    Argon2,
};
use chrono::Utc;
use poem::error::InternalServerError;
use poem::web::cookie::{Cookie, CookieJar};
use poem::web::Data;
use poem::Result;
use poem_openapi::param::Path;
use poem_openapi::{payload::Json, ApiResponse, Enum, Object, OpenApi};
use rand::RngCore;
use sea_orm::prelude::DateTimeUtc;
use sea_orm::{ActiveModelBehavior, ActiveModelTrait, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct UserApi;

#[derive(Object)]
struct NewUser {
    #[oai(validator(max_length = 64))]
    username: String,
    #[oai(validator(max_length = 32))]
    first_name: String,
    #[oai(validator(max_length = 64))]
    last_name: String,
    #[oai(validator(max_length = 131072))]
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
    LoggedIn(Json<users::Model>),
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
    WrongPassword(Json<WrongPasswordData>),
}

#[derive(Object, Deserialize)]
pub struct WrongPasswordData {
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
        _admin: AuthAdmin,
        new_user: Json<NewUser>,
        is_first_admin_registered: Data<&FirstAdminRegistered>,
        db: Data<&Db>,
    ) -> Result<CreateUserResponse> {
        let salt_string = SaltString::generate(&mut OsRng);
        let salt = salt_string.as_salt();
        let password_hash = crypto::hashing::hash(&salt, new_user.password.as_bytes())?;

        // ! Not ready for more than a single-instance deployment
        let is_first_admin_registered = &is_first_admin_registered.0.lock;

        // The new user is an admin only if no admin has been registered before
        let is_admin = !*is_first_admin_registered.read().unwrap();

        let txn = db.conn.begin().await.map_err(InternalServerError)?;

        let user: users::Model = users::ActiveModel {
            username: Set(new_user.username.clone()),
            first_name: Set(new_user.first_name.clone()),
            last_name: Set(new_user.last_name.clone()),
            password_hash: Set(password_hash.to_string()),

            ..users::ActiveModel::new()
        }
        .insert(&txn)
        .await
        .map_err(InternalServerError)?;

        if is_admin {
            println!("ehllo");
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

    #[oai(path = "/change-password", method = "post")]
    async fn change_password(
        &self,
        user: AuthUser,
        change_password: Json<ChangePassword>,
        db: Data<&Db>,
    ) -> Result<ChangePasswordResponse> {
        let user = user.0;

        if let Err(wrong_password) =
            verify_password(&user, change_password.old_password.as_bytes())?
        {
            return Ok(ChangePasswordResponse::WrongPassword(Json(wrong_password)));
        }

        let old_password_hash = user.password_hash.clone();

        let salt_string = SaltString::generate(&mut OsRng);
        let salt = salt_string.as_salt();
        let new_hash = crypto::hashing::hash(&salt, change_password.new_password.as_bytes())?;
        let mut active_user: users::ActiveModel = user.into();

        active_user.password_hash_previous = Set(Some(old_password_hash));
        active_user.password_hash = Set(new_hash.to_string());
        active_user.password_changed_at = Set(Utc::now());

        active_user
            .update(&db.conn)
            .await
            .map_err(InternalServerError)?;

        Ok(ChangePasswordResponse::Changed)
    }

    #[oai(path = "/login", method = "post")]
    async fn login(
        &self,
        user_login: Json<UserLogin>,
        cookies: &CookieJar,
        db: Data<&Db>,
    ) -> Result<LoginResponse> {
        let user = users::find_by_username(user_login.username.clone())
            .one(&db.conn)
            .await
            .map_err(InternalServerError)?
            .ok_or(LoginResponse::NotFound)?;

        verify_password(&user, user_login.password.as_bytes())?
            .map_err(|error| LoginResponse::Unauthorized(Json(error)))?;

        let mut token_bytes = [0u8; 32];
        rand::thread_rng()
            .try_fill_bytes(&mut token_bytes)
            .map_err(InternalServerError)?;

        let token = hex::encode(token_bytes);

        user_tokens::ActiveModel {
            value: Set(token.clone()),
            user_id: Set(user.id),

            ..user_tokens::ActiveModel::new()
        }
        .insert(&db.conn)
        .await
        .map_err(InternalServerError)?;

        let mut cookie = Cookie::new_with_str("_patrol_key", token);
        cookie.set_max_age(Duration::from_secs(MAX_AGE));

        cookies.add(cookie);

        Ok(LoginResponse::LoggedIn(Json(user)))
    }
}

pub fn verify_password(
    user: &users::Model,
    password: &[u8],
) -> Result<std::result::Result<(), WrongPasswordData>> {
    let hash = crypto::hashing::parse_hash(&user.password_hash)?;

    if crypto::hashing::verify(password, &hash) {
        return Ok(Ok(()));
    }

    // If password has been changed
    if let Some(password_hash_previous) = &user.password_hash_previous {
        let salt_string = SaltString::generate(&mut OsRng);
        let salt = salt_string.as_salt();
        let hash_previous = crypto::hashing::hash(&salt, password_hash_previous.as_bytes())?;

        if Argon2::default()
            .verify_password(password, &hash_previous)
            .is_ok()
        {
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
