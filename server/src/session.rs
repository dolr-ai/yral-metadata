use candid::Principal;
use ntex::web::{
    self,
    types::{Json, Path, State},
    HttpRequest,
};
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use types::ApiResult;
use utoipa::ToSchema;
use yral_canisters_client::{
    individual_user_template::{
        self, IndividualUserTemplate, SessionType, UserProfileDetailsForFrontendV2,
    },
    user_index::UserIndex,
};

use crate::{
    services::error_wrappers::{ErrorWrapper, NullOk},
    Error, Result,
};

use crate::state::AppState;

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
    path = "/update_session_as_registered/{canister_id}",
    params(
        ("canister_id" = String, Path, description = "Canister ID of the user session to update")
    ),
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
#[web::post("/update_session_as_registered/{canister_id}")]
pub async fn update_session_as_registered(
    app_state: State<AppState>,
    canister_id: Path<String>,
    http_request: HttpRequest,
) -> Result<Json<ApiResult<()>>> {
    let headers = http_request.headers();

    let Some(auth_header) = headers.get(AUTHORIZATION) else {
        return Err(Error::AuthTokenMissing);
    };

    let auth_jwt_token = auth_header
        .to_str()
        .map_err(|_| Error::AuthTokenInvalid)?
        .trim_start_matches("Bearer ");

    let jwt_claim = app_state.yral_auth_jwt.verify_token(auth_jwt_token)?;

    let referree_user_principal =
        Principal::from_text(&jwt_claim.sub).map_err(|_| Error::AuthTokenInvalid)?;

    let ic_agent = &app_state.backend_admin_ic_agent;

    let canister_id = Principal::from_text(canister_id.as_ref())?;

    let referee_individual_user_template = IndividualUserTemplate(canister_id, ic_agent);

    let referee_profile = referee_individual_user_template
        .get_profile_details_v_2()
        .await?;
    if referee_profile.principal_id != referree_user_principal {
        return Err(Error::AuthTokenInvalid);
    }

    let update_session_res = referee_individual_user_template
        .update_session_type(SessionType::RegisteredSession)
        .await?;

    if let yral_canisters_client::individual_user_template::Result22::Err(e) = update_session_res {
        return Err(Error::UpdateSession(e));
    }

    issue_referral_reward(
        &referee_individual_user_template,
        referree_user_principal,
        referee_profile,
    )
    .await?;

    Ok(Json(Ok(())))
}

async fn issue_referral_reward(
    referree_individual_user_template: &IndividualUserTemplate<'_>,
    referree_user_principal: Principal,
    profile_detials: UserProfileDetailsForFrontendV2,
) -> Result<(), Error> {
    let Some(referral_details) = profile_detials.referrer_details else {
        return Ok(());
    };

    let referrer_canister_id = referral_details.user_canister_id;

    let referrer_user_principal = referral_details.profile_owner;

    let referrer_indvidiual_template =
        IndividualUserTemplate(referrer_canister_id, referree_individual_user_template.1);
    let referee_user_index = referree_individual_user_template
        .get_well_known_principal_value(
            individual_user_template::KnownPrincipalType::CanisterIdUserIndex,
        )
        .await?;

    let referrer_user_index = referrer_indvidiual_template
        .get_well_known_principal_value(
            individual_user_template::KnownPrincipalType::CanisterIdUserIndex,
        )
        .await?;

    let (referee_user_index, referrer_user_index) = referee_user_index
        .and_then(|referee_user_id| Some((referee_user_id, referrer_user_index?)))
        .ok_or_else(|| Error::Unknown("Subnet orchestrator not found".into()))?;

    let referrer_user_index = UserIndex(referrer_user_index, referree_individual_user_template.1);

    let referee_user_index = UserIndex(referee_user_index, referree_individual_user_template.1);

    referee_user_index
        .issue_rewards_for_referral(
            referree_individual_user_template.0,
            referrer_user_principal,
            referree_user_principal,
        )
        .await?;

    referrer_user_index
        .issue_rewards_for_referral(
            referrer_canister_id,
            referrer_user_principal,
            referree_user_principal,
        )
        .await?;

    Ok(())
}
