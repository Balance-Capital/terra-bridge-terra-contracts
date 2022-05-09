use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Decimal, Uint128};
use cw0::Duration;
use cw_controllers::Claims;
use cw_storage_plus::Item;

pub const OWNER: Item<String> = Item::new("owner");