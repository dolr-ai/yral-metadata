use crate::{
    api::METADATA_FIELD,
    dragonfly::{format_to_dragonfly_key, DragonflyPool, YRAL_METADATA_KEY_PREFIX},
    notifications::traits::RedisConnection,
    services::error_wrappers::{ErrorWrapper, OkWrapper},
    state::{AppState, RedisPool},
    utils::error::{Error, Result},
};
use axum::{
    extract::{Path, State},
    Json,
};
use candid::Principal;
use email_address::EmailAddress;
use std::sync::Arc;
use types::{ApiResult, SetUserEmailMetadataReq, SetUserSignedInMetadataReq, UserMetadata};

#[utoipa::path(
    post,
    path = "/email/{user_principal}",
    params(
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    request_body = SetUserEmailMetadataReq,
    responses(
        (status = 200, description = "Set user metadata successfully", body = OkWrapper<UserMetadata>),
        (status = 400, description = "Invalid request", body = ErrorWrapper<Error>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<Error>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<Error>)
    )
)]
pub async fn set_user_email(
    State(state): State<Arc<AppState>>,
    Path(user_principal): Path<Principal>,
    Json(req): Json<SetUserEmailMetadataReq>,
) -> Result<Json<ApiResult<UserMetadata>>> {
    let principal = user_principal;

    // Add user context to Sentry
    crate::sentry_utils::add_user_context(principal, None);
    crate::sentry_utils::add_operation_breadcrumb(
        "signup",
        &format!("Setting email for user: {}", principal),
        sentry::Level::Info,
    );

    req.signature.clone().verify_identity(
        principal,
        req.payload
            .clone()
            .try_into()
            .map_err(|_| Error::AuthTokenMissing)?,
    )?;
    let result = set_user_email_impl(
        &state.redis,
        &state.dragonfly_redis,
        principal,
        req.payload.email,
        req.payload.already_signed_in,
        YRAL_METADATA_KEY_PREFIX,
    )
    .await
    .map_err(|e| {
        crate::sentry_utils::capture_api_error(
            &e,
            "/email/{user_principal}",
            Some(&principal.to_text()),
        );
        e
    })?;
    Ok(Json(Ok(result)))
}

#[utoipa::path(
    post,
    path = "/signup/{user_principal}",
    params(
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    request_body = SetUserSignedInMetadataReq,
    responses(
        (status = 200, description = "Set user metadata successfully", body = OkWrapper<UserMetadata>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<Error>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<Error>)
    )
)]
pub async fn set_signup_datetime(
    State(state): State<Arc<AppState>>,
    Path(user_principal): Path<Principal>,
    Json(req): Json<SetUserSignedInMetadataReq>,
) -> Result<Json<ApiResult<UserMetadata>>> {
    let principal = user_principal;

    // Add user context to Sentry
    crate::sentry_utils::add_user_context(principal, None);
    crate::sentry_utils::add_operation_breadcrumb(
        "signup",
        &format!("Setting signup datetime for user: {}", principal),
        sentry::Level::Info,
    );

    let res = set_signup_datetime_impl(
        &state.redis,
        &state.dragonfly_redis,
        principal,
        req.already_signed_in,
        YRAL_METADATA_KEY_PREFIX,
    )
    .await
    .map_err(|e| {
        crate::sentry_utils::capture_api_error(
            &e,
            "/signup/{user_principal}",
            Some(&principal.to_text()),
        );
        e
    })?;
    Ok(Json(Ok(res)))
}

pub async fn set_user_email_impl(
    redis_pool: &RedisPool,
    dragonfly_redis: &DragonflyPool,
    user_principal: Principal,
    email: String,
    already_signed_in: bool,
    key_prefix: &str,
) -> Result<UserMetadata> {
    let user_key = user_principal.to_text();
    let formatted_user_key = format_to_dragonfly_key(key_prefix, &user_key);

    // 1. Confirm the email is valid
    if !is_valid_email(&email) {
        return Err(Error::InvalidEmail(email));
    }

    // 2. Get Redis connection
    let mut conn = redis_pool.get().await?;
    let mut dragonfly_conn = dragonfly_redis.get().await?;

    // 3. Fetch user metadata from Redis
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user_key, METADATA_FIELD).await?;

    // 4. If metadata exists, update the KYC flag
    let Some(raw) = meta_raw else {
        return Err(Error::Unknown(format!("User `{}` not found", user_key)));
    };

    let mut meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;

    // 5. Update email only if needed
    if meta.email.is_none() {
        meta.email = Some(email);
        let updated_meta = serde_json::to_vec(&meta).map_err(Error::Deser)?;
        let _: bool = conn.hset(&user_key, METADATA_FIELD, &updated_meta).await?;
        let _: bool = dragonfly_conn
            .hset(&formatted_user_key, METADATA_FIELD, &updated_meta)
            .await?;
    }

    if !already_signed_in && meta.signup_at.is_none() {
        meta.signup_at = Some(chrono::Utc::now().timestamp());
        let updated_meta = serde_json::to_vec(&meta).map_err(Error::Deser)?;
        let _: bool = conn.hset(&user_key, METADATA_FIELD, &updated_meta).await?;
        let _: bool = dragonfly_conn
            .hset(&formatted_user_key, METADATA_FIELD, &updated_meta)
            .await?;
    }

    Ok(meta)
}

pub async fn set_signup_datetime_impl(
    redis_pool: &RedisPool,
    dragonfly_redis: &DragonflyPool,
    user_principal: Principal,
    already_signed_id: bool,
    key_prefix: &str,
) -> Result<UserMetadata> {
    let user_key = user_principal.to_text();
    let formatted_user_key = format_to_dragonfly_key(key_prefix, &user_key);

    // 2. Get Redis connection
    let mut conn = redis_pool.get().await?;
    let mut dragonfly_conn = dragonfly_redis.get().await?;

    // 3. Fetch user metadata from Redis
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user_key, METADATA_FIELD).await?;

    // 4. If metadata exists, update the KYC flag
    let Some(raw) = meta_raw else {
        return Err(Error::Unknown(format!("User `{}` not found", user_key)));
    };

    let mut meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;

    // 5. Update email only if needed
    if meta.signup_at.is_none() {
        if already_signed_id {
            meta.signup_at = Some((chrono::Utc::now() - chrono::Duration::hours(48)).timestamp());
        } else {
            meta.signup_at = Some(chrono::Utc::now().timestamp());
        }
        let updated_meta = serde_json::to_vec(&meta).map_err(Error::Deser)?;
        let _: bool = conn.hset(&user_key, METADATA_FIELD, &updated_meta).await?;
        let _: bool = dragonfly_conn
            .hset(&formatted_user_key, METADATA_FIELD, &updated_meta)
            .await?;
    }

    Ok(meta)
}

fn is_valid_email(email: &str) -> bool {
    EmailAddress::is_valid(email)
}
