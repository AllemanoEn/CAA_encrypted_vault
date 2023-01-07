use aes_gcm::{
    aead::{Aead, KeyInit,consts::U12,generic_array::GenericArray},
    Aes256Gcm, AesGcm, Key, Nonce,aes::Aes256
};

use dryoc::pwhash::*;

use serde::{Serialize, Deserialize};

/// This function encrypts a plaintext with a key and a nonce by using AES256GCM
pub(crate) fn aes256gcm_encrypt<'a>(key: &'a Key<AesGcm<Aes256, U12>>, nonce: &'a [u8; 12], plaintext: &'a [u8]) -> (Vec<u8>, GenericArray<u8, U12>) {
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
    (ciphertext, *nonce)
}

/// This function decrypts a ciphertext with a key and a nonce by using AES256GCM
pub(crate) fn aes256gcm_decrypt<'a>(key: &'a Key<AesGcm<Aes256, U12>>, nonce: &'a [u8], ciphertext: &'a [u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).expect("Decryption failed, wrong key or nonce");
    plaintext
}

/// This function recover an AES256-GCM key from a user's password with a KDF based on Argon2 in order to decrypt the corresponding user's shard
///
/// If the user doesn't exist, the function panics with a message
pub(crate) fn recover_a_shard_if_user_exists(company: &Company, user_name: &str, user_password : &Vec<u8>) -> Vec<u8> {
    let vec_users = &company.users;
    // Get the shards of the users that correspond to user1_name
    let mut user_shards = vec![];
    let mut user_salt = vec![];

    let user_exists = vec_users.iter().any(|user| {
        if user.name == user_name {
            user_shards = user.shard.clone();
            user_salt = user.salt.clone();
            true
        } else {
            false
        }
    });

    if !user_exists {
        panic!("User {} doesn't exist. Shutting down the client", user_name);
    }

    // Re-generate corresponding password hash using password hashing functions, based on Argon2
    let pwhash: VecPwHash = PwHash::hash_with_salt(
        user_password,
        user_salt,
        Config::interactive().with_salt_length(16).with_hash_length(32).with_opslimit(2).with_memlimit(67108864),
    ).expect("unable to hash password1 with salt and custom config");

    // Convert the hash to generic array to be able to use it in the cipher
    let mut hash = GenericArray::default();
    let hash_parts = pwhash.into_parts();
    hash.copy_from_slice(hash_parts.0.as_slice());

    aes256gcm_decrypt(&hash, b"unique nonce", &user_shards)
}

/// This struct represents a company
#[derive(Serialize, Deserialize)]
pub(crate) struct Company {
    pub name: String,
    pub public_key: Vec<u8>,
    pub ciphered_master_key: Vec<u8>,
    pub master_key_nonce: Vec<u8>,
    pub ciphered_private_key: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub users: Vec<User>,
    pub magic_table_index: u8,
}

/// This struct represents a magic table
#[derive(Serialize, Deserialize)]
pub(crate) struct MagicTable {
    pub list_of_ciphered_company_filename: Vec<Vec<u8>>,
    pub list_of_company_filename_nonce: Vec<Vec<u8>>,
}

/// This struct represents a user
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct User {
    pub name: String,
    pub shard: Vec<u8>,
    pub salt: Vec<u8>
}

/// This struct represents a company's file
#[derive(Serialize, Deserialize)]
pub(crate) struct CompanyFile {
    pub ciphered_filename: Vec<u8>,
    pub filename_nonce: Vec<u8>,
    pub ciphered_content: Vec<u8>,
    pub content_nonce: Vec<u8>,
    pub salt: Vec<u8>
}

