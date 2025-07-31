use crate::{
    api::METADATA_FIELD,
    kyc::KycService,
    notifications::traits::RedisConnection,
    state::RedisPool,
    utils::error::{Error, Result},
};
use crate::{
    services::error_wrappers::{ErrorWrapper, OkWrapper},
    state::AppState,
};
use candid::Principal;
use ntex::web::{
    self,
    types::{Json, Path, State},
};
use types::{error::ApiError, ApiResult, SetKycMetadataReq, SetKycMetadataRes, UserMetadata};

#[utoipa::path(
    post,
    path = "/kyc/{user_principal}",
    params(
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    request_body = SetKycMetadataReq,
    responses(
        (status = 200, description = "Set user metadata successfully", body = OkWrapper<SetKycMetadataRes>),
        (status = 400, description = "Invalid request", body = ErrorWrapper<Error>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<Error>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<Error>)
    )
)]
#[web::post("/kyc/{user_principal}")]
async fn mark_kyc_completed(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<SetKycMetadataReq>,
) -> Result<Json<ApiResult<()>>> {
    let result = mark_kyc_completed_impl(&state.redis, *user_principal, req.0.inquiry_id).await?;
    Ok(Json(Ok(result)))
}

pub async fn mark_kyc_completed_impl(
    redis_pool: &RedisPool,
    user_principal: Principal,
    inquiry_id: String,
) -> Result<()> {
    let user_key = user_principal.to_text();

    // 1. Confirm the KYC was successfully completed via your KYC service
    check_kyc_completed(user_principal, inquiry_id)
        .await
        .map_err(|e| Error::Unknown(e.to_string()))?;

    // 2. Get Redis connection
    let mut conn = redis_pool.get().await?;

    // 3. Fetch user metadata from Redis
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user_key, METADATA_FIELD).await?;

    // 4. If metadata exists, update the KYC flag
    let Some(raw) = meta_raw else {
        return Err(Error::UserNotFound(format!("User `{}` not found", user_key)));
    };

    let mut meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;

    // 5. Update KYC flag only if needed
    if !meta.kyc_completed {
        meta.kyc_completed = true;
        let updated_meta = serde_json::to_vec(&meta).map_err(Error::Deser)?;
        let _: bool = conn.hset(&user_key, METADATA_FIELD, &updated_meta).await?;
    }

    Ok(())
}

async fn check_kyc_completed(
    user_principal: Principal,
    inquiry_id: String,
) -> Result<(), ApiError> {
    KycService::check_kyc_completed(user_principal, inquiry_id).await
}
