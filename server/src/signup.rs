use crate::{
    api::METADATA_FIELD,
    notifications::traits::RedisConnection,
    state::RedisPool,
    utils::error::{Error, Result},
};
use crate::{
    services::error_wrappers::{ErrorWrapper, OkWrapper},
    state::AppState,
};
use candid::Principal;
use email_address::EmailAddress;
use ntex::web::{
    self,
    types::{Json, Path, State},
};
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
#[web::post("/email/{user_principal}")]
async fn set_user_email(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<SetUserEmailMetadataReq>,
) -> Result<Json<ApiResult<UserMetadata>>> {
    let result = set_user_email_impl(&state.redis, *user_principal, req.0.email).await?;
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
#[web::post("/signup/{user_principal}")]
async fn set_signup_datetime(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<SetUserSignedInMetadataReq>,
) -> Result<Json<ApiResult<UserMetadata>>> {
    let res =
        set_signup_datetime_impl(&state.redis, *user_principal, req.0.already_signed_in).await?;
    Ok(Json(Ok(res)))
}

pub async fn set_user_email_impl(
    redis_pool: &RedisPool,
    user_principal: Principal,
    email: String,
) -> Result<UserMetadata> {
    let user_key = user_principal.to_text();

    // 1. Confirm the email is valid
    if !is_valid_email(&email) {
        return Err(Error::InvalidEmail(email));
    }

    // 2. Get Redis connection
    let mut conn = redis_pool.get().await?;

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
    }

    if meta.signup_at.is_none() {
        meta.signup_at = Some(chrono::Utc::now().timestamp());
        let updated_meta = serde_json::to_vec(&meta).map_err(Error::Deser)?;
        let _: bool = conn.hset(&user_key, METADATA_FIELD, &updated_meta).await?;
    }

    Ok(meta)
}

pub async fn set_signup_datetime_impl(
    redis_pool: &RedisPool,
    user_principal: Principal,
    already_signed_id: bool,
) -> Result<UserMetadata> {
    let user_key = user_principal.to_text();

    // 2. Get Redis connection
    let mut conn = redis_pool.get().await?;

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
            meta.signup_at = Some((chrono::Utc::now() - chrono::Duration::hours(24)).timestamp());
        } else {
            meta.signup_at = Some(chrono::Utc::now().timestamp());
        }
        let updated_meta = serde_json::to_vec(&meta).map_err(Error::Deser)?;
        let _: bool = conn.hset(&user_key, METADATA_FIELD, &updated_meta).await?;
    }

    Ok(meta)
}

fn is_valid_email(email: &str) -> bool {
    EmailAddress::is_valid(email)
}
