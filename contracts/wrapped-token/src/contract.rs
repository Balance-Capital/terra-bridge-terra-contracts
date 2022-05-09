#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coin, to_binary, Addr, BankMsg, Binary, Decimal, Deps, DepsMut, DistributionMsg, Env,
    MessageInfo, QuerierWrapper, Response, StakingMsg, StdError, StdResult, Uint128, WasmMsg,
};

use cw2::set_contract_version;
use cw20_base::allowances::{
    execute_burn_from, execute_decrease_allowance, execute_increase_allowance, execute_send_from,
    execute_transfer_from, query_allowance,
};
use cw20_base::contract::{
    instantiate as cw20_base_instantiate, query as cw20_base_query,
    execute as cw20_base_execute, execute_burn as cw20_base_execute_burn, execute_mint as cw20_base_execute_mint
};
use cw20_base::msg::{
    ExecuteMsg as Cw20BaseExecuteMsg
};
use cw20_base::state::{MinterData, TokenInfo, TOKEN_INFO};
use crate::state::{OWNER};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:wrapped-token";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    let addr_owner = deps.api.addr_validate(&msg.owner)?;
    let addr_minter = deps.api.addr_validate(&msg.minter)?;

    // store token info using cw20-base format
    let data = TokenInfo {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
        total_supply: Uint128::zero(),
        // set self as minter, so we can properly execute mint and burn
        mint: Some(MinterData {
            minter: addr_minter,
            cap: None,
        }),
    };
    TOKEN_INFO.save(deps.storage, &data)?;

    OWNER.save(deps.storage, &msg.owner)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::BurnWrapped { amount, to } => execute_burn(deps, env, info, amount, to.as_str()),
        ExecuteMsg::MintWrapped { recipient, amount } => execute_mint(deps, env, info, recipient, amount),
        ExecuteMsg::ChangeMinter { account } => execute_change_minter(deps, info, account),
        ExecuteMsg::Transfer { recipient, amount } => {
            let res = cw20_base::contract::execute_transfer(deps, env, info, recipient, amount);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::Burn { amount } => {
            let res = cw20_base::contract::execute_burn(deps, env, info, amount);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::Send {
            contract,
            amount,
            msg,
        } => {
            let res = cw20_base::contract::execute_send(deps, env, info, contract, amount, msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::Mint { recipient, amount } => {
            let msg = Cw20BaseExecuteMsg::Mint { recipient, amount };
            let res = cw20_base_execute(deps, env.clone(), info.clone(), msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::IncreaseAllowance {
            spender,
            amount,
            expires,
        } => {
            let msg = Cw20BaseExecuteMsg::IncreaseAllowance {
                spender,
                amount,
                expires,
            };
            let res = cw20_base_execute(deps, env.clone(), info.clone(), msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::DecreaseAllowance {
            spender,
            amount,
            expires,
        } => {
            let msg = Cw20BaseExecuteMsg::DecreaseAllowance {
                spender,
                amount,
                expires,
            };
            let res = cw20_base_execute(deps, env.clone(), info.clone(), msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        } 
        ExecuteMsg::TransferFrom {
            owner,
            recipient,
            amount,
        } => {
            let msg = Cw20BaseExecuteMsg::TransferFrom {
                owner,
                recipient,
                amount,
            };
            let res = cw20_base_execute(deps, env.clone(), info.clone(), msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::BurnFrom { owner, amount } => {
            let msg = Cw20BaseExecuteMsg::BurnFrom { owner, amount };
            let res = cw20_base_execute(deps, env.clone(), info.clone(), msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::SendFrom {
            owner,
            contract,
            amount,
            msg,
        } => {
            let msg = Cw20BaseExecuteMsg::SendFrom {
                owner,
                contract,
                amount,
                msg,
            };
            let res = cw20_base_execute(deps, env.clone(), info.clone(), msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::UpdateMarketing {
            project,
            description,
            marketing,
        } => {
            let msg = Cw20BaseExecuteMsg::UpdateMarketing {
                project,
                description,
                marketing,
            };
            let res = cw20_base_execute(deps, env.clone(), info.clone(), msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
        ExecuteMsg::UploadLogo(logo) => {
            let msg = Cw20BaseExecuteMsg::UploadLogo(logo);
            let res = cw20_base_execute(deps, env.clone(), info.clone(), msg);
            match res {
                Ok(response) => Ok(response),
                Err(error) => Err(ContractError::from(error))
            }
        }
    }
}

pub fn execute_change_minter(deps: DepsMut, info: MessageInfo, account: Addr) -> Result<Response, ContractError> {
    let owner = OWNER.load(deps.storage)?;
    if (owner != info.sender) {
        return Err(ContractError::Unauthorized { });
    }
    TOKEN_INFO.update(deps.storage, |mut info| -> StdResult<_> {
        let minterdata = Some(MinterData {
            minter: account.clone(),
            cap: None,
        });
        info.mint = minterdata;
        Ok(info)
    })?;
    Ok(Response::new()
        .add_attribute("account", account.to_string())
    )
}

pub fn execute_burn(deps: DepsMut, env: Env, info: MessageInfo, amount: Uint128, to: &str) -> Result<Response, ContractError> {
    let burn_res = cw20_base_execute_burn(deps, env, info.clone(), amount);
    match burn_res {
        Ok(response) => Ok(
            response
                .add_attribute("sender", &info.sender)
                .add_attribute("to", to)
                .add_attribute("amount", amount)
        ),
        Err(v) => Err(ContractError::from(v))
    }
}

pub fn execute_mint(deps: DepsMut, env: Env, info: MessageInfo, recipient: String, amount: Uint128) -> Result<Response, ContractError> {
    let account = deps.api.addr_validate(&recipient)?;
    let mint_res = cw20_base_execute_mint(deps, env, info, account.to_string(), amount);
    match mint_res {
        Ok(response) => Ok(
            response
                .add_attribute("sender", account.to_string())
                .add_attribute("amount", amount)
        ),
        Err(v) => Err(ContractError::from(v))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    cw20_base_query(deps, _env, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockQuerier, MOCK_CONTRACT_ADDR,
    };
    use cosmwasm_std::{
        coins, Coin, CosmosMsg, Decimal, FullDelegation, OverflowError, OverflowOperation,
        Validator,
    };
    use cw0::{Duration, DAY, HOUR, WEEK};
    use cw_controllers::Claim;
}
