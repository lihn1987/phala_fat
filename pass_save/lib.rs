#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;
use pink::chain_extension::{ SigType};


#[pink::contract(env=PinkEnvironment)]
mod pass_save {
    use super::pink;
    use pink::logger::{Level, Logger};
    use pink::{http_get, PinkEnvironment};
    use pink::chain_extension::signing::derive_sr25519_key;

    use fat_utils::attestation;
    use ink_prelude::{
        string::{String, ToString},
        vec::Vec,
    };
    use ink_storage::traits::SpreadAllocate;
    use ink_storage::Mapping;
    use scale::{Decode, Encode};

    use fat_badges::issuable::IssuableRef;
    // 加密相关
    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct PassSave {
        user_password: Mapping<AccountId, [u8;32]>
    }

    /// Errors that can occur upon calling this contract.
    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        BadgeContractNotSetUp,
        InvalidUrl,
        RequestFailed,
        NoClaimFound,
        InvalidAddressLength,
        InvalidAddress,
        NoPermission,
        InvalidSignature,
        UsernameAlreadyInUse,
        AccountAlreadyInUse,
        FailedToIssueBadge,
        CannotEncrypt,
        CannotDecrypt
    }

    /// Type alias for the contract's result type.
    // pub type Result<T> = core::result::Result<T, Error>;

    impl PassSave {
        #[ink(constructor)]
        pub fn new() -> Self {
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(b"gist-attestation-key");
            // Save sender as the contract admin
            let admin = Self::env().caller();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
            })
        }
        
        // 产生一个[u8;32]的密码，返回值用于调试
        #[ink(message)]
        pub fn create_pwd(&mut self) -> [u8;32] {
            let caller = Self::env().caller();
            match self.user_password.get(caller) {
                Some(pwd) => {
                    return pwd.clone();
                }
                None => {
                    let mut iv_key:[u8;32] = [0;32];
                    let privkey = derive_sr25519_key(b"asdf");
                    for i in 0..32 {
                        iv_key[i] = privkey[i];
                    }
                    self.user_password.insert(caller, &iv_key);
                    return iv_key;
                }
            }
            
        }
        #[ink(message)]
        pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, Error> {
            // if offset_bytes % (BLOCK_BYTES as u64) != 0 {
            //     panic!(
            //         "Offset must be in multiples of block length of {} bytes",
            //         BLOCK_BYTES
            //     );
            // }
            let caller = Self::env().caller();
            // self.create_pwd();
            let passwd = &self.user_password.get(caller).unwrap();
            let key = Key::from_slice(passwd);
            let cipher = Aes256Gcm::new(key);
            // TODO: increase IV by offset / BLOCK_LEN
            let iv: [u8;12] = self.user_password.get(caller).unwrap()[..12].try_into().expect("should");
            let nonce = Nonce::from_slice(&iv); // 96-bits; unique per message

            let ciphertext = cipher
                .encrypt(nonce, plaintext.as_ref())
                .map_err(|_| Error::CannotEncrypt)?;
            Ok(ciphertext)
        }

        // #[ink(message)]
        // pub fn aaa(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, Error> {
        //     Ok([1;12].try_into().unwrap())
        // }

        // #[ink(message)]
        // pub fn bbb(&self, plaintext: Vec<u8>) -> Vec<u8> {
        //     [1;12].try_into().unwrap()
        // }

        // #[ink(message)]
        // pub fn ccc(&self, plaintext: Vec<u8>) -> String {
        //     "123456".to_string()
        // }

        #[ink(message)]
        pub fn decrypt(&self,  ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
            // if offset_bytes % (BLOCK_BYTES as u64) != 0 {
            //     panic!(
            //         "Offset must be in multiples of block length of {} bytes",
            //         BLOCK_BYTES
            //     );
            // }
            let caller = Self::env().caller();
            // self.create_pwd();
            let passwd = &self.user_password.get(caller).unwrap();
            let key = Key::from_slice(passwd);
            let cipher = Aes256Gcm::new(key);
            // TODO: increase IV by offset / BLOCK_LEN
            let iv: [u8;12] = self.user_password.get(caller).unwrap()[..12].try_into().expect("should");
            let nonce = Nonce::from_slice(&iv); // 96-bits; unique per message

            let plaintext = cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|_| Error::CannotDecrypt)?;
            Ok(plaintext)
        }


    }
}
