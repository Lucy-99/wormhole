//#![allow(unused_mut)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::FungibleToken;
use near_sdk::collections::LazyOption;
use near_sdk::json_types::{Base64VecU8, U128};

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedSet};
use near_sdk::{
    env, ext_contract, near_bindgen, AccountId, Balance, Gas, PanicOnDefault, Promise,
    PromiseError, PromiseOrValue, PromiseResult, PublicKey,
};
use serde::{de, Deserialize, Serialize};

use near_sdk::serde_json::Value;

use near_sdk::utils::is_promise_success;

use near_sys as sys;

use hex;

pub mod byte_utils;
pub mod state;

use crate::byte_utils::{get_string_from_32, ByteUtils};

// near_sdk::setup_alloc!();

const CHAIN_ID_NEAR: u16 = 15;
const CHAIN_ID_SOL: u16 = 1;

const BRIDGE_TOKEN_BINARY: &'static [u8] =
    include_bytes!("../../ft/target/wasm32-unknown-unknown/release/ft.wasm");

/// Initial balance for the BridgeToken contract to cover storage and related.
const BRIDGE_TOKEN_INIT_BALANCE: Balance = 5_760_000_000_000_000_000_000;

/// Gas to initialize BridgeToken contract.
const BRIDGE_TOKEN_NEW: Gas = Gas(100_000_000_000_000);

/// Gas to call mint method on bridge token.
const MINT_GAS: Gas = Gas(10_000_000_000_000);

const NO_DEPOSIT: Balance = 0;

#[ext_contract(ext_ft_contract)]
pub trait FtContract {
    fn new(metadata: FungibleTokenMetadata, asset_meta: Vec<u8>, seq_number: u64);
    fn update_ft(&self, metadata: FungibleTokenMetadata, asset_meta: Vec<u8>, seq_number: u64);
}

#[ext_contract(ext_worm_hole)]
pub trait Wormhole {
    fn verify_vaa(&self, vaa: String) -> u32;
    fn publish_message(&self, data: Vec<u8>) -> u64;
}

#[ext_contract(ext_portal)]
pub trait ExtPortal {
    fn finish_deploy(&self, tkey: Vec<u8>, us: &mut UnwindState);
}

#[derive(Serialize, Deserialize)]
pub struct UnwindState {
    amount: Balance,
    sender_id: AccountId,
}

impl UnwindState {
    pub fn new() -> Self {
        Self {
            amount: 0,
            sender_id: AccountId::new_unchecked("".to_string()),
        }
    }

    pub fn unwind(&mut self) {
        // This will envolve over time...

        if self.amount > 0 {
            // Lets attempt to send the money back on error
            Promise::new(self.sender_id.clone()).transfer(self.amount);
            self.amount = 0;
        }
    }
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Portal {
    booted: bool,
    core: AccountId,
    dups: UnorderedSet<Vec<u8>>,
    good: UnorderedSet<Vec<u8>>,
    owner_pk: PublicKey,
    registrations: LookupMap<u16, Vec<u8>>,
    tokens: UnorderedSet<Vec<u8>>,
}

impl Default for Portal {
    fn default() -> Self {
        Self {
            booted: false,
            core: AccountId::new_unchecked("".to_string()),
            dups: UnorderedSet::new(b"d".to_vec()),
            good: UnorderedSet::new(b"g".to_vec()),
            owner_pk: env::signer_account_pk(),
            registrations: LookupMap::new(b"c".to_vec()),
            tokens: UnorderedSet::new(b"t".to_vec()),
        }
    }
}

fn vaa_register_chain(storage: &mut Portal, vaa: state::ParsedVAA, us: &mut UnwindState) {
    let data: &[u8] = &vaa.payload;
    let target_chain = data.get_u16(33);
    let chain = data.get_u16(35);

    if (target_chain != CHAIN_ID_NEAR) && (target_chain != 0) {
        us.unwind();
        env::panic_str("InvalidRegisterChainChain");
    }

    if storage.registrations.contains_key(&chain) {
        us.unwind();
        env::panic_str("DuplicateChainRegistration");
    }

    storage.registrations.insert(&chain, &data[37..69].to_vec());

    env::log_str(&format!(
        "register chain {} to {}",
        chain,
        hex::encode(&data[37..69])
    ));
}

fn vaa_upgrade_contract(storage: &mut Portal, vaa: state::ParsedVAA, us: &mut UnwindState) {
    let data: &[u8] = &vaa.payload;
    let chain = data.get_u16(33);
    if chain != CHAIN_ID_NEAR {
        us.unwind();
        env::panic_str("InvalidContractUpgradeChain");
    }

    us.unwind();
    env::panic_str("ContractUpgradesNotImplemented");
}

fn vaa_governance(storage: &mut Portal, vaa: state::ParsedVAA, us: &mut UnwindState, gov_idx: u32) {
    if gov_idx != vaa.guardian_set_index {
        us.unwind();
        env::panic_str("InvalidGovernanceSet");
    }

    if (CHAIN_ID_SOL != vaa.emitter_chain)
        || (hex::decode("0000000000000000000000000000000000000000000000000000000000000004")
            .unwrap()
            != vaa.emitter_address)
    {
        us.unwind();
        env::panic_str("InvalidGovernanceEmitter");
    }

    let data: &[u8] = &vaa.payload;
    let action = data.get_u8(32);

    match action {
        1u8 => vaa_register_chain(storage, vaa, us),
        2u8 => vaa_upgrade_contract(storage, vaa, us),
        _ => {
            us.unwind();
            env::panic_str("InvalidGovernanceAction")
        }
    }
}

fn vaa_transfer(storage: &mut Portal, vaa: state::ParsedVAA, us: &mut UnwindState) {
    let data: &[u8] = &vaa.payload[1..];
    let amount = data.get_u256(0);
    let token_address = data.get_bytes32(32).to_vec();
    let token_chain = data.get_u16(64);
    let recipient = data.get_bytes32(66).to_vec();
    let recipient_chain = data.get_u16(98);
    let fee = data.get_u256(100);

    us.unwind();
    env::panic_str("vaa_transfer");
}

fn vaa_asset_meta(storage: &mut Portal, vaa: state::ParsedVAA, us: &mut UnwindState) {
    let data: &[u8] = &vaa.payload[1..];

    let mut off = 0;
    while off < 34 && data[off] == 0 {
        off = off + 1;
    }
    let tkey = data[off..34].to_vec();
    let token_chain = data.get_u16(32);
    let mut decimals = data.get_u8(34);
    let symbol = data.get_bytes32(35).to_vec();
    let name = data.get_bytes32(67).to_vec();

    if token_chain == CHAIN_ID_NEAR {
        us.unwind();
        env::panic_str("CannotAttestNearAssets");
    }

    let wname = get_string_from_32(&name) + " (Wormhole)";

    // Stick some useful meta-data into the asset to allow us to map backwards from a on-chain asset to the wormhole meta data
    let reference = hex::encode(&tkey);
    let ref_hash = env::sha256(&reference.as_bytes().to_vec());
    let bridge_token_account = format!("{}.{}", reference, env::current_account_id());

    if !env::is_valid_account_id(bridge_token_account.as_bytes()) {
        us.unwind();
        env::panic_str("InvalidAccountId");
    }

    let bridge_token_account_id: AccountId = AccountId::new_unchecked(bridge_token_account.clone());

    // Decimals are capped at 8 in wormhole
    if decimals > 8 {
        decimals = 8;
    }

    let ft = FungibleTokenMetadata {
        spec: FT_METADATA_SPEC.to_string(),
        name: wname,
        symbol: get_string_from_32(&symbol),
        icon: Some("".to_string()), // Is there ANY way to supply this?
        reference: Some(reference.clone()),
        reference_hash: Some(Base64VecU8::from(ref_hash)),
        decimals: decimals,
    };

    if storage.tokens.contains(&tkey) {
        ext_ft_contract::ext(bridge_token_account_id)
            .update_ft(ft, data.to_vec(), vaa.sequence)
            .as_return();
    } else {
        let v = BRIDGE_TOKEN_BINARY.to_vec();

        if env::attached_deposit()
            < BRIDGE_TOKEN_INIT_BALANCE + (v.len() as u128 * env::storage_byte_cost())
        {
            us.unwind();
            env::panic_str("Not enough attached deposit to complete bridge token creation");
        }

        Promise::new(bridge_token_account_id.clone())
            .create_account()
            .transfer(BRIDGE_TOKEN_INIT_BALANCE + (v.len() as u128 * env::storage_byte_cost()))
            .add_full_access_key(storage.owner_pk.clone())
            .deploy_contract(v)
            // Lets initialize it with useful stuff
            .then(ext_ft_contract::ext(bridge_token_account_id).new(
                ft,
                data.to_vec(),
                vaa.sequence,
            ))
            // And then lets tell us we are done!
            .then(ext_portal::ext(env::current_account_id()).finish_deploy(tkey, us))
            .as_return();
    }
}

fn vaa_transfer_with_payload(storage: &mut Portal, vaa: state::ParsedVAA, us: &mut UnwindState) {
    let data: &[u8] = &vaa.payload[1..];
    let amount = data.get_u256(0);
    let token_address = data.get_bytes32(32).to_vec();
    let token_chain = data.get_u16(64);
    let recipient = data.get_bytes32(66).to_vec();
    let recipient_chain = data.get_u16(98);
    let fee = data.get_u256(100);
    let payload = &data[132..];

    us.unwind();
    env::panic_str("vaa_transfer_with_payload");
}

pub fn submit_vaa_callback_work(
    storage: &mut Portal,
    vaa: String,
    us: &mut UnwindState,
    gov_idx: u32,
) {
    env::log_str(&"submit_vaa_callback_work::top");

    let h = hex::decode(vaa).expect("invalidVaa");

    let vaa = state::ParsedVAA::parse(&h);

    if vaa.version != 1 {
        us.unwind();
        env::panic_str("InvalidVersion");
    }

    let data: &[u8] = &vaa.payload;

    let governance = data[0..32]
        == hex::decode("000000000000000000000000000000000000000000546f6b656e427269646765").unwrap();
    let action = data.get_u8(0);

    if !governance && action == 2u8 {
        if storage.good.contains(&vaa.hash) {
            env::log_str(&"submit_vaa_callback_work::remove");
            storage.good.remove(&vaa.hash);
        } else {
            env::log_str(&"submit_vaa_callback_work::insert and return");
            storage.good.insert(&vaa.hash);
            return;
        }
    }

    env::log_str(&"submit_vaa_callback_work::getting_work_done");

    // Check if VAA with this hash was already accepted
    if storage.dups.contains(&vaa.hash) {
        us.unwind();
        env::panic_str("alreadyExecuted");
    }
    storage.dups.insert(&vaa.hash);

    if governance {
        vaa_governance(storage, vaa, us, gov_idx);
        return;
    }

    env::log_str(&format!("looking up chain {}", vaa.emitter_chain));

    if !storage.registrations.contains_key(&vaa.emitter_chain) {
        us.unwind();
        env::panic_str("ChainNotRegistered");
    }

    if storage.registrations.get(&vaa.emitter_chain).unwrap() != vaa.emitter_address {
        us.unwind();
        env::panic_str("InvalidRegistration");
    }

    env::log_str(&"submit_vaa_callback_work::branching_to_actions");

    match action {
        1u8 => vaa_transfer(storage, vaa, us),
        2u8 => vaa_asset_meta(storage, vaa, us),
        3u8 => vaa_transfer_with_payload(storage, vaa, us),
        _ => {
            us.unwind();
            env::panic_str("InvalidPortalAction");
        }
    }
}

#[near_bindgen]
impl Portal {
    #[payable]
    pub fn submit_vaa(&mut self, vaa: String) -> Promise {
        env::log_str(&"submit_vaa::start");
        let mut us: UnwindState = UnwindState::new();

        let h = hex::decode(&vaa).expect("invalidVaa");

        // Please optimize this next time you are bored and just have it do the hash calculation...
        let pvaa = state::ParsedVAA::parse(&h);

        us.sender_id = env::signer_account_id();

        let p: Promise;
        if self.good.contains(&pvaa.hash) {
            env::log_str(&"submit_vaa::bypass");
            submit_vaa_callback_work(self, vaa, &mut us, 0);
            p = Promise::new(env::signer_account_id())
        } else {
            env::log_str(&"submit_vaa::mainline");
            us.amount = env::attached_deposit();

            p = ext_worm_hole::ext(self.core.clone())
                .verify_vaa(vaa.clone())
                .then(Self::ext(env::current_account_id()).submit_vaa_callback(vaa, &mut us))
        }
        return p.then(Self::ext(env::current_account_id()).do_log("submit_vaa::end".to_string()));
        //        env::log_str(&"submit_vaa::end");
    }

    #[private]
    pub fn do_log(&mut self, msg: String) {
        env::log_str(&msg);

        if !is_promise_success() {
            unsafe {
                sys::panic();
            }
        }
    }

    #[private]
    pub fn finish_deploy(&mut self, tkey: Vec<u8>, us: &mut UnwindState) {
        if is_promise_success() {
            env::log_str(&"We made it... what does that mean?");
            self.tokens.insert(&tkey);
        } else {
            //us.unwind(); // what does this mean?
            env::panic_str("bad deploy");
        }
    }

    #[private] // So, all of wormhole security rests in this one statement?
    pub fn submit_vaa_callback(
        &mut self,
        vaa: String,
        us: &mut UnwindState,
        #[callback_result] gov_idx: Result<u32, PromiseError>,
    ) {
        // Is this even needed anymore?
        if (env::promise_results_count() != 1)
            || (env::predecessor_account_id() != env::current_account_id())
        {
            us.unwind();
            env::panic_str("BadPredecessorAccount");
        }

        // Is there anyway to confirm the person I called and is
        // calling me back here is the person is the core_contract?

        if gov_idx.is_err() {
            us.unwind();
            env::panic_str("vaaVerifyFail");
        }

        submit_vaa_callback_work(self, vaa, us, gov_idx.unwrap());
    }

    pub fn boot_portal(&mut self, core: String) {
        if self.owner_pk != env::signer_account_pk() {
            env::panic_str("invalidSigner");
        }

        if self.booted {
            env::panic_str("NoDonut");
        }
        self.booted = true;
        self.core = AccountId::try_from(core.clone()).unwrap();
    }
}
