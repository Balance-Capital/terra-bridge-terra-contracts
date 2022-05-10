use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub owner: String,
    // whitelist

    pub threshold: Uint128,
    pub nonce: Uint128
}

pub const PUB_KEY: Item<String> = Item::new("pub_key");
pub const STATE: Item<State> = Item::new("state");
pub const BRIDGE_STATE: Item<bool> = Item::new("bridge_state");