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
    PromiseOrValue, PromiseResult, StorageUsage,
};

use near_sdk::serde_json::Value;

use hex;

// near_sdk::setup_alloc!();

const CHAIN_ID_NEAR: u16 = 15;
const CHAIN_ID_SOL: u16 = 1;

#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct FTContractMeta {
    metadata: FungibleTokenMetadata,
    vaa: Vec<u8>,
    sequence: u64,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct FTContract {
    token: FungibleToken,
    meta: LazyOption<FTContractMeta>,
    controller: AccountId,
}

#[near_bindgen]
impl FTContract {
    fn on_account_closed(&mut self, account_id: AccountId, balance: Balance) {
        env::log_str(&format!("Closed @{} with {}", account_id, balance));
    }

    fn on_tokens_burned(&mut self, account_id: AccountId, amount: Balance) {
        env::log_str(&format!("Account @{} burned {}", account_id, amount));
    }

    #[init]
    pub fn new(
        metadata: FungibleTokenMetadata,
        asset_meta: Vec<u8>,
        seq_number: u64,
    ) -> Self {
        assert!(!env::state_exists(), "Already initialized");

        metadata.assert_valid();

        let meta = FTContractMeta {
            metadata: metadata,
            vaa: asset_meta,
            sequence: seq_number,
        };

        Self {
            token: FungibleToken::new(b"ft".to_vec()),
            meta: LazyOption::new(b"md".to_vec(), Some(&meta)),
            controller: env::predecessor_account_id(),
        }
    }

    pub fn update_ft(&mut self, metadata: FungibleTokenMetadata, asset_meta: Vec<u8>, seq_number: u64) {
        if env::predecessor_account_id() != self.controller {
            env::panic_str("CrossContractInvalidCaller");
        }

        if seq_number <= self.meta.get().unwrap().sequence {
            env::panic_str("AssetMetaDataRollback");
        }

        let meta = FTContractMeta {
            metadata: metadata,
            vaa: asset_meta,
            sequence: seq_number,
        };

        self.meta.replace(&meta);
    }

//    #[payable]
//    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
//        assert_eq!(
//            env::predecessor_account_id(),
//            self.controller,
//            "Only controller can call mint"
//        );
//
//        self.storage_deposit(Some(account_id.as_str().try_into().unwrap()), None);
//        self.token.internal_deposit(&account_id, amount.into());
//    }
//
//    #[payable]
//    pub fn withdraw(&mut self, amount: U128, recipient: String) -> Promise {
//        self.check_not_paused(PAUSE_WITHDRAW);
//
//        assert_one_yocto();
//        Promise::new(env::predecessor_account_id()).transfer(1);
//
//        self.token
//            .internal_withdraw(&env::predecessor_account_id(), amount.into());
//
//        ext_bridge_token_factory::finish_withdraw(
//            amount.into(),
//            recipient,
//            &self.controller,
//            NO_DEPOSIT,
//            FINISH_WITHDRAW_GAS,
//        )
//    }

    pub fn account_storage_usage(&self) -> StorageUsage {
        self.token.account_storage_usage
    }

    /// Return true if the caller is either controller or self
    pub fn controller_or_self(&self) -> bool {
        let caller = env::predecessor_account_id();
        caller == self.controller || caller == env::current_account_id()
    }

}

near_contract_standards::impl_fungible_token_core!(FTContract, token, on_tokens_burned);
near_contract_standards::impl_fungible_token_storage!(FTContract, token, on_account_closed);

#[near_bindgen]
impl FungibleTokenMetadataProvider for FTContract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.meta.get().unwrap().metadata
    }
}
