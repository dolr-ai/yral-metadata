use crate::{
    api::METADATA_FIELD,
    dragonfly::{format_to_dragonfly_key, DragonflyPool, YRAL_METADATA_KEY_PREFIX},
    notifications::traits::RedisConnection,
    services::error_wrappers::{ErrorWrapper, OkWrapper},
    state::AppState,
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

/// Optimized with pipelines for batch writes
pub async fn set_user_email_impl(
    dragonfly_redis: &DragonflyPool,
    user_principal: Principal,
    email: String,
    already_signed_in: bool,
    key_prefix: &str,
) -> Result<UserMetadata> {
    let user_key = user_principal.to_text();

    // 1. Confirm the email is valid
    if !is_valid_email(&email) {
        return Err(Error::InvalidEmail(email));
    }

    let key_prefix = key_prefix.to_string();
    let email_clone = email.clone();

    dragonfly_redis
        .execute_with_retry(|mut conn| {
            let user_key = user_key.clone();
            let key_prefix = key_prefix.clone();
            let email = email_clone.clone();

            async move {
                let formatted_user_key = format_to_dragonfly_key(&key_prefix, &user_key);

                // Fetch user metadata
                let meta_raw: Option<Box<[u8]>> =
                    conn.hget(&formatted_user_key, METADATA_FIELD).await?;

                let Some(raw) = meta_raw else {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Parse,
                        "User not found",
                    )));
                };

                let mut meta: UserMetadata = serde_json::from_slice(&raw).map_err(|e| {
                    redis::RedisError::from((
                        redis::ErrorKind::Parse,
                        "Deserialization failed",
                        e.to_string(),
                    ))
                })?;
                let mut needs_update = false;

                // Update email only if needed
                if meta.email.is_none() {
                    meta.email = Some(email);
                    needs_update = true;
                }

                if !already_signed_in && meta.signup_at.is_none() {
                    meta.signup_at = Some(chrono::Utc::now().timestamp());
                    needs_update = true;
                }

                // Write updates directly
                if needs_update {
                    let updated_meta = serde_json::to_vec(&meta).map_err(|e| {
                        redis::RedisError::from((
                            redis::ErrorKind::Parse,
                            "Serialization failed",
                            e.to_string(),
                        ))
                    })?;

                    conn.hset(&formatted_user_key, METADATA_FIELD, &updated_meta)
                        .await?;
                }

                Ok(meta)
            }
        })
        .await
        .map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("User not found") {
                Error::Unknown(format!("User `{}` not found", user_key))
            } else {
                Error::from(e)
            }
        })
}

/// Optimized with pipelines for batch writes
pub async fn set_signup_datetime_impl(
    dragonfly_redis: &DragonflyPool,
    user_principal: Principal,
    already_signed_id: bool,
    key_prefix: &str,
) -> Result<UserMetadata> {
    let user_key = user_principal.to_text();
    let key_prefix = key_prefix.to_string();

    dragonfly_redis
        .execute_with_retry(|mut conn| {
            let user_key = user_key.clone();
            let key_prefix = key_prefix.clone();

            async move {
                let formatted_user_key = format_to_dragonfly_key(&key_prefix, &user_key);

                // Fetch user metadata
                let meta_raw: Option<Box<[u8]>> =
                    conn.hget(&formatted_user_key, METADATA_FIELD).await?;

                let Some(raw) = meta_raw else {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Parse,
                        "User not found",
                    )));
                };

                let mut meta: UserMetadata = serde_json::from_slice(&raw).map_err(|e| {
                    redis::RedisError::from((
                        redis::ErrorKind::Parse,
                        "Deserialization failed",
                        e.to_string(),
                    ))
                })?;

                // Update signup_at only if needed
                if meta.signup_at.is_none() {
                    if already_signed_id {
                        meta.signup_at =
                            Some((chrono::Utc::now() - chrono::Duration::hours(48)).timestamp());
                    } else {
                        meta.signup_at = Some(chrono::Utc::now().timestamp());
                    }
                    let updated_meta = serde_json::to_vec(&meta).map_err(|e| {
                        redis::RedisError::from((
                            redis::ErrorKind::Parse,
                            "Serialization failed",
                            e.to_string(),
                        ))
                    })?;

                    conn.hset(&formatted_user_key, METADATA_FIELD, &updated_meta)
                        .await?;
                }

                Ok(meta)
            }
        })
        .await
        .map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("User not found") {
                Error::Unknown(format!("User `{}` not found", user_key))
            } else {
                Error::from(e)
            }
        })
}

fn is_valid_email(email: &str) -> bool {
    EmailAddress::is_valid(email)
}
