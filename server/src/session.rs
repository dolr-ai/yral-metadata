use candid::Principal;
use ntex::web::{
    self,
    types::{Json, Path, State},
    HttpRequest,
};
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use types::{ApiResult, CanisterSessionRegisteredRes};
use yral_canisters_client::{
    individual_user_template::{self, Canister, IndividualUserTemplate, Ok, SessionType},
    user_index::UserIndex,
};

use crate::utils::error::Error as APIError;

use std::{error::Error, result::Result};

use crate::state::AppState;

#[derive(Serialize, Deserialize)]
pub struct YralAuthClaim {
    aud: String,
    exp: u64,
    iat: u64,
    iss: String,
    sub: String,
    nonce: Option<String>,
    ext_is_anonymous: bool,
}

#[web::post("/update_session_as_registered/{canister_id}")]
async fn update_session_as_registered(
    app_state: State<AppState>,
    canister_id: Path<String>,
    http_request: HttpRequest,
) -> Result<Json<CanisterSessionRegisteredRes>, APIError> {
    let headers = http_request.headers();

    let Some(auth_header) = headers.get(AUTHORIZATION) else {
        return Err(APIError::AuthTokenMissing);
    };

    let auth_jwt_token = auth_header
        .to_str()
        .map_err(|_| APIError::AuthTokenInvalid)?
        .trim_start_matches("Bearer ");

    let jwt_claim = app_state.yral_auth_jwt.verify_token(auth_jwt_token)?;

    let referree_user_principal =
        Principal::from_text(&jwt_claim.sub).map_err(|_| APIError::AuthTokenInvalid)?;

    let ic_agent = &app_state.backend_admin_ic_agent;

    let canister_id =
        Principal::from_text(canister_id.as_ref()).map_err(|e| APIError::Unknown(e.to_string()))?;

    let referee_individual_user_template = IndividualUserTemplate(canister_id, ic_agent);

    let mut api_result = CanisterSessionRegisteredRes {
        success: true,
        error: None,
        referral_success: true,
    };

    match referee_individual_user_template
        .update_session_type(SessionType::RegisteredSession)
        .await
        .map_err(|e| APIError::Unknown(e.to_string()))?
    {
        yral_canisters_client::individual_user_template::Result22::Ok(_) => {
            if let Err(e) =
                issue_referral_reward(&referee_individual_user_template, referree_user_principal)
                    .await
            {
                log::error!("Error issuing referral reward: {}", e);
                api_result.referral_success = false;
                api_result.error = Some(e.to_string());
            }
        }
        yral_canisters_client::individual_user_template::Result22::Err(e) => {
            log::error!("Error updating session type: {}", e);
            api_result.success = false;
            api_result.error = Some(e.to_string());
        }
    };

    return Ok(Json(api_result));
}

async fn issue_referral_reward(
    referree_individual_user_template: &IndividualUserTemplate<'_>,
    referree_user_principal: Principal,
) -> Result<(), Box<dyn Error>> {
    let referral_details = referree_individual_user_template
        .get_profile_details_v_2()
        .await?
        .referrer_details;

    if let Some(referral_details) = referral_details {
        let referrer_canister_id = referral_details.user_canister_id;

        let referrer_user_principal = referral_details.profile_owner;

        let referrer_indvidiual_template =
            IndividualUserTemplate(referrer_canister_id, referree_individual_user_template.1);
        let referree_user_index = referree_individual_user_template
            .get_well_known_principal_value(
                individual_user_template::KnownPrincipalType::CanisterIdUserIndex,
            )
            .await?;

        let referrer_user_index = referrer_indvidiual_template
            .get_well_known_principal_value(
                individual_user_template::KnownPrincipalType::CanisterIdUserIndex,
            )
            .await?;

        let issue_referral_reward_result = match (referrer_user_index, referree_user_index) {
            (Some(referrer_user_index), Some(referree_user_index)) => {
                let referrer_user_index =
                    UserIndex(referrer_user_index, referree_individual_user_template.1);

                let referee_user_index =
                    UserIndex(referree_user_index, referree_individual_user_template.1);

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
            _ => Err("Subnet orchestrator not found".into()),
        };

        return issue_referral_reward_result;
    }

    Ok(())
}
