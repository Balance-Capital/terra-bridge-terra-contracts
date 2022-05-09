use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response,
    StdError, StdResult, Uint128,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::ops::Deref;

use secp256k1::{Signature, Secp256k1, Message, SecretKey, PublicKey};
// use ecdsa::Signature;

use crate::ethereum::{
    decode_address, ethereum_address_raw, get_recovery_param, verify_transaction,
};
use crate::msg::{
    InstantiateMsg, QueryMsg
};

pub const VERSION: &str = "crypto-verify-v2";

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    Ok(Response::default())
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    match msg {
        
    }
}

pub fn my_verify() -> StdResult<bool> {
    let secp = Secp256k1::new();
    // let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    // let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let secret_key = SecretKey::from_slice(&hex::decode("42d16f3a3a0480e605d0ca88e6e77a7d5f2d7f1cf6a2c1982be3b4fdeae54715").unwrap()).unwrap();
    let public_key = PublicKey::from_slice(&hex::decode("03094b68a608df879e58fefa4e8c27bbf08d9742f82699bf61b1dc9e6dcf8b0b2f").unwrap()).unwrap();
    // This is unsafe unless the supplied byte slice is the output of a cryptographic hash function.
    // See the above example for how to use this library together with `bitcoin_hashes`.
    // a41438c730b01795861d49a7ae41babd257c2fee8a8e5cd19a739b85514a1855
    // 16862482441981422717247528811510312493142233210247111891171279635252209603243206190
    // 282384252988274992309302181154113424512054158827816522821546243118343824216103
    // 32221983081117195195901894723016715513615332462291118016313417616551823822424100
    // 3,25,167,9,104,50,91,188,64,90,90,145,0,29,228,197,161,19,142,4,143,142,179,123,146,155,212,248,242,36,69,228,132
    // 136,35,15,80,176,246,221,118,88,83,39,15,213,115,213,155,150,36,174,102,158,127,16,175,21,3,237,195,255,208,235,59,65,150,244,124,46,132,62,130,98,121,148,117,210,214,140,184,246,169,141,115,122,127,39,152,174,101,177,65,140,107,197,200

    // Hash
    // 4c8f18581c0167eb90a761b4a304e009b924f03b619a0c0e8ea3adfce20aee64
    // PUB KEY
    // 2,157,237,123,173,45,171,86,93,108,3,40,179,152,187,222,110,255,92,30,9,2,101,5,243,255,21,229,15,107,217,36,79
    // SIGNATURE

    let mut hasher = Keccak256::new();
    // hasher.update(format!("\x19Ethereum Signed Message:\n{}", message.len()));
    hasher.update("asdf");
    let hash = hasher.finalize();
    let message = Message::from_slice(&hash).unwrap();

    let sig = secp.sign_ecdsa(&message, &secret_key);
    println!("Signature ================================== {:?}", sig);
    let sig = Signature::from_compact(&hex::decode("9efc27edf7daa7fcc0ab8575ee15af44443a5a11a847f3cbee618f7f370e1c0952271d28589210facf0a693ec4cfe108648a8bc58d4170e40d1083038636c357").unwrap()).
        expect("compact signatures are 64 bytes; DER signatures are 68-72 bytes");
    // 3045022100cf739f71c218cb887f6d7e1d9f1c1e02c8d1395f5b72aab642050ce9145d527b02204cc5bac88c4d4dd302638bdc330a2e540decdddc8e4be9f69312863248afaf5d
    // 16f70e5d21bff88955129b931bfdc2361d011dc6cec87a41a803166764458f8820807c2714cfcbdf832564558af2e24961a1b073cc0297101d2acf3ddfc43558
    // 1861011351928311817912710522312462162151688027741861081032121651114013623017224315617274254841165126118114239254827824610414319110448562231120820721659088243184702027201
    // 1861011351928311817912710522312462162151688027741861081032121651114013623017224315617274254841165126118114239254827824610414319110448562231120820721659088243184702027201
    let res = secp.verify_ecdsa(&message, &sig, &public_key).is_ok();
    Ok(res)
    // unimplemented!()
    // Ok(sig.verify(&message, &public_key).is_ok());
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{
        from_slice, Binary, OwnedDeps, RecoverPubkeyError, StdError, VerificationError,
    };
    use hex_literal::hex;

    const CREATOR: &str = "creator";

    // const SECP256K1_MESSAGE_HEX: &str = "5c868fedb8026979ebd26f1ba07c27eedf4ff6d10443505a96ecaf21ba8c4f0937b3cd23ffdc3dd429d4cd1905fb8dbcceeff1350020e18b58d2ba70887baa3a9b783ad30d3fbf210331cdd7df8d77defa398cdacdfc2e359c7ba4cae46bb74401deb417f8b912a1aa966aeeba9c39c7dd22479ae2b30719dca2f2206c5eb4b7";
    // const SECP256K1_SIGNATURE_HEX: &str = "207082eb2c3dfa0b454e0906051270ba4074ac93760ba9e7110cd9471475111151eb0dbbc9920e72146fb564f99d039802bf6ef2561446eb126ef364d21ee9c4";
    // const SECP256K1_PUBLIC_KEY_HEX: &str = "04051c1ee2190ecfb174bfe4f90763f2b4ff7517b70a2aec1876ebcfd644c4633fb03f3cfbd94b1f376e34592d9d41ccaf640bb751b00a1fadeb0c01157769eb73";

    // // TEST 3 test vector from https://tools.ietf.org/html/rfc8032#section-7.1
    // const ED25519_MESSAGE_HEX: &str = "af82";
    // const ED25519_SIGNATURE_HEX: &str =   "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
    // const ED25519_PUBLIC_KEY_HEX: &str =
    //     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

    // // Signed text "connect all the things" using MyEtherWallet with private key b5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7
    // // const ETHEREUM_MESSAGE: &str = "connect all the things";
    // // const ETHEREUM_SIGNATURE_HEX: &str = "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";
    // // const ETHEREUM_SIGNER_ADDRESS: &str = "0x12890D2cce102216644c59daE5baed380d84830c";

    // const ETHEREUM_MESSAGE: &str = "connect all the things";
    // const ETHEREUM_SIGNATURE_HEX: &str = "2e0b9a188bf66071f637a295de79f84fdec434e1ac41cd11fc5f8c8d4aca191460f4fdd3e1608adf20b7d4fcce03eb37cd8838e430699d3add6e185ac788e71b00";
    // const ETHEREUM_SIGNER_ADDRESS: &str =
    //     "0x97e6da7e678f9a8d7134fa5fc9d8605dc0ab66dfa67520c01f949645ec83ef63";

    // // TEST 2 test vector from https://tools.ietf.org/html/rfc8032#section-7.1
    // const ED25519_MESSAGE2_HEX: &str = "72";
    // const ED25519_SIGNATURE2_HEX: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
    // const ED25519_PUBLIC_KEY2_HEX: &str =
    //     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

    // fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
    //     let mut deps = mock_dependencies();
    //     let msg = InstantiateMsg {};
    //     let info = mock_info(CREATOR, &[]);
    //     let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
    //     assert_eq!(0, res.messages.len());
    //     deps
    // }

    // #[test]
    // fn instantiate_works() {
    //     setup();
    // }

    #[test]
    fn mytest() {
        let res = my_verify().unwrap();
        assert_eq!(res, true);
    }

}
