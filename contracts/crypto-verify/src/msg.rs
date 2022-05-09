use cosmwasm_std::{Binary, Deps, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct VerifyResponse {
    pub verifies: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ListVerificationsResponse {
    pub verification_schemes: Vec<String>,
}

pub(crate) fn list_verifications(_deps: Deps) -> Vec<String> {
    vec!["secp256k1".into(), "ed25519".into(), "ed25519_batch".into()]
}
