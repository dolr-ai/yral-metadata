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
    let user = user_principal.to_text();
    let mut conn = redis_pool.get().await?;
    check_kyc_completed(user_principal, inquiry_id)
        .await
        .map_err(|e| Error::Unknown(e.to_string()))?;
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;

    if let Some(raw) = meta_raw {
        let mut meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;
        meta.kyc_completed = true;

        let meta_raw = serde_json::to_vec(&meta).map_err(Error::Deser)?;
        let _: bool = conn.hset(&user, METADATA_FIELD, &meta_raw).await?;
    }

    Ok(())
}

async fn check_kyc_completed(
    user_principal: Principal,
    inquiry_id: String,
) -> Result<(), ApiError> {
    KycService::check_kyc_completed(user_principal, inquiry_id).await
}
