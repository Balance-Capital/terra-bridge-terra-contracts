use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Unverified")]
    Unverified {},

    #[error("BridgeNotLive")]
    BridgeNotLive {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiseerror/1.0.21/thiserror/ for details.
}