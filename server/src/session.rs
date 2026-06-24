use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use candid::Principal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use types::ApiResult;
use utoipa::ToSchema;
use yral_canisters_client::{
    ic::USER_INFO_SERVICE_ID,
    user_info_service::{Result_, SessionType as UserServiceSessionType, UserInfoService},
};

use crate::{
    services::error_wrappers::{ErrorWrapper, NullOk},
    state::AppState,
    Error, Result,
};

#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct UpdateUserSessionRequest {
    user_principal: String,
    user_canister: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct YralAuthClaim {
    aud: String,
    exp: u64,
    iat: u64,
    iss: String,
    sub: String,
    nonce: Option<String>,
    ext_is_anonymous: bool,
}

#[utoipa::path(
    post,
    path = "/v2/update_session_as_registered",
    request_body = UpdateUserSessionRequest,
    responses(
        (status = 200, description = "Session updated successfully", body = NullOk), // OkWrapper<()> panics for some reason
        (status = 400, description = "Invalid request or canister ID", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 401, description = "Unauthorized - Auth token missing or invalid", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<crate::utils::error::Error>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn update_session_as_registered_v2(
    State(app_state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req_payload): Json<UpdateUserSessionRequest>,
) -> Result<Json<ApiResult<()>>> {
    crate::sentry_utils::add_operation_breadcrumb(
        "session",
        &format!("Update session v2 for user: {}", req_payload.user_principal),
        sentry::Level::Info,
    );

    let Some(auth_header) = headers.get("Authorization") else {
        crate::sentry_utils::add_operation_breadcrumb(
            "session",
            "Auth token missing",
            sentry::Level::Warning,
        );
        return Err(Error::AuthTokenMissing);
    };

    let auth_jwt_token = auth_header
        .to_str()
        .map_err(|_| Error::AuthTokenInvalid)?
        .trim_start_matches("Bearer ");

    let _jwt_claim = app_state.yral_auth_jwt.verify_token(auth_jwt_token)?;

    let ic_agent = &app_state.backend_admin_ic_agent;

    let user_canister = Principal::from_text(req_payload.user_canister.clone())?;
    let user_principal = Principal::from_text(req_payload.user_principal.clone())?;

    // Individual user canisters have been decommissioned; all session updates
    // now go through the user_info_service canister.
    if user_canister != USER_INFO_SERVICE_ID {
        crate::sentry_utils::add_operation_breadcrumb(
            "session",
            &format!(
                "Unexpected canister id for session update: {} (expected user_info_service)",
                user_canister.to_text()
            ),
            sentry::Level::Warning,
        );
    }

    crate::sentry_utils::add_canister_call_breadcrumb(
        &user_canister.to_text(),
        "update_session_type",
        true,
    );
    let user_info_service = UserInfoService(USER_INFO_SERVICE_ID, ic_agent);

    let result = user_info_service
        .update_session_type(user_principal, UserServiceSessionType::RegisteredSession)
        .await
        .map_err(|e| {
            crate::sentry_utils::add_canister_call_breadcrumb(
                &user_canister.to_text(),
                "update_session_type",
                false,
            );
            e
        })?;

    if let Result_::Err(e) = result {
        crate::sentry_utils::add_operation_breadcrumb(
            "session",
            &format!("Update session failed: {}", e),
            sentry::Level::Error,
        );
        return Err(Error::UpdateSession(e));
    }

    Ok(Json(Ok(())))
}

// TODO: migrate to user_info_service/user_post_service
// The old v1 endpoint relied on IndividualUserTemplate canister calls
// (get_profile_details_v2, get_well_known_principal_value, update_session_type)
// and UserIndex::issue_rewards_for_referral, none of which have equivalents
// in user_info_service. Referral reward logic needs to be reimplemented
// against the new canister architecture before this endpoint can be restored.
//
// #[utoipa::path(
//     post,
//     path = "/update_session_as_registered/{canister_id}",
//     params(
//         ("canister_id" = String, Path, description = "Canister ID of the user session to update")
//     ),
//     responses(
//         (status = 200, description = "Session updated successfully", body = NullOk),
//         (status = 400, description = "Invalid request or canister ID", body = ErrorWrapper<crate::utils::error::Error>),
//         (status = 401, description = "Unauthorized - Auth token missing or invalid", body = ErrorWrapper<crate::utils::error::Error>),
//         (status = 500, description = "Internal server error", body = ErrorWrapper<crate::utils::error::Error>)
//     ),
//     security(
//         ("bearer_auth" = [])
//     )
// )]
// pub async fn update_session_as_registered(
//     State(app_state): State<Arc<AppState>>,
//     Path(canister_id): Path<String>,
//     headers: HeaderMap,
// ) -> Result<Json<ApiResult<()>>> {
//     ...
// }
//
// async fn issue_referral_reward(...) { ... }
