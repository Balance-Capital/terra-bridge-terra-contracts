#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128, Addr,
    WasmMsg, SubMsg, WasmQuery, QueryRequest
};
use cw2::set_contract_version;

use sha2::{Digest, Sha256};
use sha3::Keccak256;
// use secp256k1::{Signature, Secp256k1, Message, SecretKey, PublicKey};

use cw20::{
    BalanceResponse
};

use wrapped_token::msg::{ExecuteMsg as WrappedTokenExecuteMsg/* , QueryMsg as WrappedTokenExecuteMsg */};

use crate::error::ContractError;
use crate::msg::{CountResponse, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{State, STATE, PUB_KEY, BRIDGE_STATE};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:bridge-minter";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = State {
        threshold: Uint128::from(msg.threshold as u128),
        nonce: Uint128::from(msg.nonce as u128),
        owner: info.sender.to_string(),
    };

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    STATE.save(deps.storage, &state)?;
    let state1 = STATE.load(deps.storage)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", state1.owner)
        .add_attribute("threshold", state1.threshold.to_string())
        .add_attribute("nonce", state1.nonce.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SetPubKey ( pub_key ) => execute_set_pub_key(deps, info, &pub_key),
        ExecuteMsg::Mint { _token, _to, _amount, _txHash, _signature } => 
            execute_mint(deps, _token, _to, _amount, &_txHash, &_signature)
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetState() => to_binary(&query_get_state(deps)?)
    }
}

pub fn execute_mint (deps: DepsMut, _token: String, _to: String, _amount: Uint128, _txHash: &str, _signature: &str ) -> Result<Response, ContractError> {

    let bridge_state = BRIDGE_STATE.load(deps.storage)?;
    if !bridge_state {
        return Err(ContractError::Unverified {})
    }

    let state = STATE.load(deps.storage)?;
    let mut nonce: Uint128 = state.nonce;
    let hash = getk256message(nonce, _token.clone(), _to.clone(), _amount, _txHash)?;
    let addr_token = deps.api.addr_validate(&_token)?;
    let addr_to = deps.api.addr_validate(&_to)?;
    let is_verified = verify(deps.as_ref(), &hex::decode(&hash).unwrap(), _signature)?;

    match is_verified {
        true => {
            let res = wrapped_token_mint(_token.clone(), addr_to, _amount)?;
            // let balance: BalanceResponse = get_balnace(deps.as_ref(), _token, _to).unwrap();
            STATE.update(deps.storage, |mut info| -> StdResult<_> {
                info.nonce = nonce.wrapping_add(Uint128::from(1u128));
                nonce = info.nonce;
                Ok(info)
            })?;
            Ok(Response::new()
                .add_submessages(res)
                .add_attribute("nonce", nonce.to_string())
                // .add_attribute("balance", balance.balance)
                .add_attribute("verify", "ok")
            )
        },
        false => Err(ContractError::Unverified {})
    }
}

pub fn execute_change_bridge_state(deps: DepsMut, new_bridge_state: bool, _txHash: &str, _signature: &str) -> Result<Response, ContractError> {
    let mut hasher = Keccak256::new();
    let bridge_state_to_string: &str;
    match new_bridge_state {
        true => {
            bridge_state_to_string = "1";
        },
        false => {
            bridge_state_to_string = "0";
        }
    }
    // hasher.update(format!("\x19Ethereum Signed Message:\n{}", message.len()));
    hasher.update(bridge_state_to_string.to_string());
    // hasher.update(_txHash.to_owned());
    let hash = hasher.finalize();
    let hash = format!("{:X}", hash);
    let is_verified = verify(deps.as_ref(), &hex::decode(&hash).unwrap(), _signature)?;

    match is_verified {
        true => {
            BRIDGE_STATE.save(deps.storage, &new_bridge_state)?;
            Ok(Response::new()
                .add_attribute("bridge_state", bridge_state_to_string))
        },
        false => Err(ContractError::Unverified {})
    }
}

// fn get_balnace(deps: Deps, token: String, user: String) -> StdResult<BalanceResponse> {
//     let query_msg = wrapped_token::msg::QueryMsg::Balance { address: user };
//     let req = QueryRequest::Wasm(WasmQuery::Smart {
//         contract_addr: token,
//         msg: to_binary(&query_msg)?
//     });
//     let balance: BalanceResponse = deps.querier.query(&req)?;
//     Ok(balance)
// }

fn wrapped_token_mint(token: String, addr_to: Addr, amount: Uint128) -> StdResult<Vec<SubMsg>> {
    let msg = WrappedTokenExecuteMsg::MintWrapped {
        recipient: addr_to.to_string(),
        amount: amount
    };
    let exec = WasmMsg::Execute {
        contract_addr: token,
        msg: to_binary(&msg)?,
        funds: vec![]
    };
    Ok(vec![SubMsg::new(exec)])
}

pub fn execute_set_pub_key (deps: DepsMut, info: MessageInfo, pub_key: &str) -> Result<Response, ContractError> {
    let config = STATE.may_load(deps.storage)?;
    if (config.is_none() || config.as_ref().unwrap().owner != info.sender) {
        return Err(ContractError::Unauthorized {});
    }
    PUB_KEY.save(deps.storage,&String::from(pub_key))?;
    Ok(Response::new()
        .add_attribute("pub_key", pub_key))
}

pub fn query_get_state(deps: Deps) -> StdResult<Response> {
    let config = STATE.may_load(deps.storage)?;
    match (config) {
        Some(v) => {
            Ok(Response::new()
                .add_attribute("owner", v.owner)
            )
        },
        None => {
            Ok(Response::new()
                .add_attribute("owner", "no")
            )
        }
    }
}

pub fn query_getk256message(_nonce: Uint128, _token: String, _to: String, _amount: Uint128, _txHash: &str) -> StdResult<Response> {
    let mut hasher = Keccak256::new();
    // hasher.update(format!("\x19Ethereum Signed Message:\n{}", message.len()));
    hasher.update(_nonce.to_string());
    hasher.update(_token);
    hasher.update(_to);
    hasher.update(_amount.to_string());
    hasher.update(_txHash);
    // hasher.update(_txHash.to_owned());
    let hash = hasher.finalize();
    let string_hash = format!("{:X}", hash);

    Ok(Response::new()
        .add_attribute("hasher", string_hash))
}

pub fn getk256message(_nonce: Uint128, _token: String, _to: String, _amount: Uint128, _txHash: &str) -> StdResult<String> {
    let mut hasher = Keccak256::new();
    // hasher.update(format!("\x19Ethereum Signed Message:\n{}", message.len()));
    hasher.update(_nonce.to_string());
    hasher.update(_token);
    hasher.update(_to);
    hasher.update(_amount.to_string());
    hasher.update(_txHash);
    // hasher.update(_txHash.to_owned());
    let hash = hasher.finalize();
    let string_hash = format!("{:X}", hash);

    Ok(string_hash)
}


// pub fn decrypt_signature(signature: &[u8], pub_key: &[u8]) -> StdResult<Response> {

// }

fn verify(deps: Deps, hash: &[u8], signature: &str) -> Result<bool, ContractError> {
    let str_pub_key : String = PUB_KEY.may_load(deps.storage)?.unwrap_or_default();
    let result = deps
        .api
        .secp256k1_verify(hash.as_ref(), 
            &hex::decode(&signature).unwrap(), 
            &hex::decode(&str_pub_key).unwrap());
    match result {
        Ok(verifies) => Ok( verifies ),
        Err(err) => Err(ContractError::Unverified {})
    }
    // Ok(res)
}

// fn verify()

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies_with_balances, mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary, Addr, coin};
    use hex;

    #[test]
    fn test_minter() {
        let mut deps = mock_dependencies(&[]);
        let msg = InstantiateMsg {
            nonce: 11,
            threshold: 1,
        };
        let info = mock_info("creator", &[]);
        // let res = instantiate(deps.as_mut(), mock_env(), info, msg);
        let res = query_getk256message(
            Uint128::from(11u128), 
            String::from("token"), 
            String::from("to"), 
            Uint128::from(100u128), 
            "include<stdio.h>8819d((*&"
        ).unwrap();

        println!("Response: {:?}", res.attributes[0]);
        assert_eq!(
            res,
            Response::new()
                .add_attribute("hasher", "A34C188BA5326AFFA4DDB4B090A734E2D0156E2C3BEF6C224559CA33C40FB644")
        );
    }
    
    // pubkey
    // 02d4ec262439a688594c0b620380770f30ceb4ccd52211b793f1841ade7682c295
    // privkey
    // 28e008520f59c727c56e8de237c8c4f663355cd316c454a3c9e1dcdcafe16afb
    // sig
    // ff905d344592a9b0f0f89f7f46937c4d73c865ea914e48ca2a6920347c049d6a08c1561f2c384f96a814fb495c76451168bf3f838e2cfbe30113526ea9abcb1c
    #[test]
    fn test_verify_minter() {
        let mut deps = mock_dependencies(&[]);
        let info = mock_info("creator", &[]);
        // let mut deps = mock_dependencies_with_balances(&[("token", &[coin(100, "coin")])]);
        // let info = mock_info("creator", &coins(1000, "earth"));
        // let hash = getk256message(
        //     Uint128::from(11u128), 
        //     String::from("token"), 
        //     String::from("to"), 
        //     Uint128::from(100u128), 
        //     "include<stdio.h>8819d((*&"
        // ).unwrap();
        // let sig = &hex::decode("ff905d344592a9b0f0f89f7f46937c4d73c865ea914e48ca2a6920347c049d6a08c1561f2c384f96a814fb495c76451168bf3f838e2cfbe30113526ea9abcb1c").unwrap();
        let instantiatmsg = InstantiateMsg {
            nonce: 11,
            threshold: 1,
        };
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), instantiatmsg).unwrap();
        println!("{:?}", res.attributes);
        assert_eq!(4, res.attributes.len());

        let res: Response = from_binary(&query(deps.as_ref(), mock_env(), QueryMsg::GetState()).unwrap()).unwrap();
        println!("{:?}", res.attributes);
        assert_eq!(1, res.attributes.len());

        let sub_key_msg = ExecuteMsg::SetPubKey(String::from("032dc6b3a5d0df59e5a47fbb8e516d0fc1a75fe8ef0f959053e1172b997fbfdad8"));
        let res = execute(deps.as_mut(), mock_env(), info.clone(), sub_key_msg).unwrap();
        println!("{:?}", res.attributes);
        assert_eq!(1, res.attributes.len());

        // 7d8bf2d44d8605e3109fa038d3507940b62495e7e901b33333609d8ce51e4ecd49fd0aef5800be2abd3fd8122f9dbfd2b5c9fa5b34b3d476ce1081bbf1fdf009
        let sig = "5a98c1b85c43fe08d144410d967badc498db55765b4d886df709788101ad77c80714e83d9141417d313aff7d2e7b45d999e9aa1ce45fd8d86b0a4c1f7f8b0fff";

        let mint_msg = ExecuteMsg::Mint { 
            _token: String::from("terra1skc56hrrg92zj8xxj6lyjlt2l2m8q8sf832sqm"),
            _to: String::from("terra1ej058juh27zw6e6c6a9gsgflfvtuaaff56m7dg"),
            _amount: Uint128::from(100u128),
            _txHash: String::from("include<stdio.h>8819d((*&"),
            _signature: String::from(sig)
        };
        let res = execute(deps.as_mut(), mock_env(), info.clone(), mint_msg).unwrap();
        println!("result ================================> {:?}", res.attributes);
            
        // let is_verify = verify(deps.as_mut(), &hex::decode(hash).unwrap(), 
        //     "ff905d344592a9b0f0f89f7f46937c4d73c865ea914e48ca2a6920347c049d6a08c1561f2c384f96a814fb495c76451168bf3f838e2cfbe30113526ea9abcb1c").unwrap();
        // assert_eq!(is_verify, true);
    }
}
