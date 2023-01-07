use crate::ressources::{aes256gcm_encrypt, Company, User, CompanyFile, MagicTable};

use shamir::SecretData;
use std::{collections::HashMap,fs::File,io::prelude::*};
use base64;
use dryoc::{dryocbox::*,pwhash::*};

use aes_gcm::{aead::{KeyInit, OsRng,generic_array::GenericArray}, Aes256Gcm};

/// Initialize the server architecture for the first time
/// with fake companies, files and users
///
/// This function is called only once when the server is launched for the first time
///
/// Watch out ! This initialization function contains all the keys and passwords of the server
/// It should be used only once and then deleted
///
pub fn init_server_architecture(){

    let master_key_256 = Aes256Gcm::generate_key(&mut OsRng);
    println!("[INFO Server log] Master key of 256 bits generated");

    let intermediate_key_256 = Aes256Gcm::generate_key(&mut OsRng);
    let intermediate_key_256_string = base64::encode(intermediate_key_256);
    println!("[INFO Server log] Intermediate key of 256 bits generated");

    let secret_data = SecretData::with_secret(&intermediate_key_256_string, 2);

    let shard1 = secret_data.get_share(1);
    let shard2 = secret_data.get_share(2);
    let shard3 = secret_data.get_share(3);
    let shard4 = secret_data.get_share(4);
    println!("[INFO Server log] 4 shards generated");

    let keypair = KeyPair::gen();
    println!("[INFO Server log] Key pair generated");

    let private_key_256_bytes = keypair.secret_key.as_slice();
    let private_key_256_ciphered = aes256gcm_encrypt(&master_key_256, b"unique nonce", &private_key_256_bytes);
    println!("[INFO Server log] Private key ciphered");

    let master_key_256_bytes = master_key_256.as_slice();
    let master_key_256_ciphered= aes256gcm_encrypt(&intermediate_key_256, b"unique nonce", &master_key_256_bytes);
    println!("[INFO Server log] Master key ciphered");

    let password1 = b"password1";
    // Generate password hash using password hashing functions, based on Argon2
    let pwhash1 = PwHash::hash_with_defaults(password1).expect("unable to hash");
    // Convert the hash to generic array to be able to use it in the cipher
    let mut hash1 = GenericArray::default();
    let hash1_parts = pwhash1.into_parts();
    hash1.copy_from_slice(hash1_parts.0.as_slice());

    // Create a cipher with the hash as key to cipher the shard
    let shard1_bytes = match shard1 { Ok(shard1) => shard1.to_vec(), Err(e) => panic!("Error: {:?}", e) };
    let shard1_ciphered = aes256gcm_encrypt(&hash1, b"unique nonce", &shard1_bytes);
    println!("[INFO Server log] User1's shard ciphered");

    let password2 = b"password2";
    let pwhash2 = PwHash::hash_with_defaults(password2).expect("unable to hash");
    let mut hash2 = GenericArray::default();
    let hash2_parts = pwhash2.into_parts();
    hash2.copy_from_slice(hash2_parts.0.as_slice());

    let shard2_bytes = match shard2 { Ok(shard2) => shard2.to_vec(), Err(e) => panic!("Error: {:?}", e) };
    let shard2_ciphered = aes256gcm_encrypt(&hash2, b"unique nonce", &shard2_bytes);
    println!("[INFO Server log] User2's shard ciphered");

    let password3 = b"password3";
    let pwhash3 = PwHash::hash_with_defaults(password3).expect("unable to hash");
    let mut hash3 = GenericArray::default();
    let hash3_parts = pwhash3.into_parts();
    hash3.copy_from_slice(hash3_parts.0.as_slice());

    let shard3_bytes = match shard3 { Ok(shard3) => shard3.to_vec(), Err(e) => panic!("Error: {:?}", e) };
    let shard3_ciphered = aes256gcm_encrypt(&hash3, b"unique nonce", &shard3_bytes);
    println!("[INFO Server log] User3's shard ciphered");

    let password4 = b"password4";
    let pwhash4 = PwHash::hash_with_defaults(password4).expect("unable to hash");
    let mut hash4 = GenericArray::default();
    let hash4_parts = pwhash4.into_parts();
    hash4.copy_from_slice(hash4_parts.0.as_slice());

    let shard4_bytes = match shard4 { Ok(shard4) => shard4.to_vec(), Err(e) => panic!("Error: {:?}", e) };
    let shard4_ciphered = aes256gcm_encrypt(&hash4, b"unique nonce", &shard4_bytes);
    println!("[INFO Server log] User4's shard ciphered");

    // Create all users and their respective data
    let user1 = User{
        name: "Alice".to_string(),
        shard: shard1_ciphered.0,
        salt: hash1_parts.1.to_vec()
    };
    let user2 = User{
        name: "Bob".to_string(),
        shard: shard2_ciphered.0,
        salt: hash2_parts.1.to_vec()
    };
    let user3 = User{
        name: "Carol".to_string(),
        shard: shard3_ciphered.0,
        salt: hash3_parts.1.to_vec()
    };
    let user4 = User{
        name: "Eve".to_string(),
        shard: shard4_ciphered.0,
        salt: hash4_parts.1.to_vec()
    };

    // Create three files that contains "secret" data
    let company_file1_name = b"file1.txt";
    let company_file1_content = b"This is the secret content of the first file";

    // Concatenate the company file name 1 and the master key
    let master_and_company_file1_name = [company_file1_name, master_key_256_bytes].concat();

    let file_pwhash1 = PwHash::hash_with_defaults(&master_and_company_file1_name).expect("unable to hash");
    let mut file_hash1 = GenericArray::default();
    let file_hash1_parts = file_pwhash1.into_parts();
    file_hash1.copy_from_slice(file_hash1_parts.0.as_slice());

    let company_file1_content_ciphered = aes256gcm_encrypt(&file_hash1, b"unique nonce", company_file1_content);
    let company_file1_name_ciphered = aes256gcm_encrypt(&master_key_256, b"unique nonce", company_file1_name);

    // Same as above but for the second file
    let company_file2_name = b"file2.txt";
    let company_file2_content = b"This is the secret content of the second file";

    let master_and_company_file2_name = [company_file2_name, master_key_256_bytes].concat();

    let file_pwhash2 = PwHash::hash_with_defaults(&master_and_company_file2_name).expect("unable to hash");
    let mut file_hash2 = GenericArray::default();
    let file_hash2_parts = file_pwhash2.into_parts();
    file_hash2.copy_from_slice(file_hash2_parts.0.as_slice());

    let file_content2_ciphered = aes256gcm_encrypt(&file_hash2, b"unique nonce", company_file2_content);
    let file_name2_ciphered = aes256gcm_encrypt(&master_key_256, b"unique nonce", company_file2_name);

    // Same as above but for the third file
    let company_file3_name = b"file3.txt";
    let company_file3_content = b"This is the secret content of the third file";

    let master_and_company_file3_name = [company_file3_name, master_key_256_bytes].concat();

    let file_pwhash3 = PwHash::hash_with_defaults(&master_and_company_file3_name).expect("unable to hash");
    let mut file_hash3 = GenericArray::default();
    let file_hash3_parts = file_pwhash3.into_parts();
    file_hash3.copy_from_slice(file_hash3_parts.0.as_slice());

    let file_content3_ciphered = aes256gcm_encrypt(&file_hash3, b"unique nonce", company_file3_content);
    let file_name3_ciphered = aes256gcm_encrypt(&master_key_256, b"unique nonce", company_file3_name);

    // Declare the company files struct
    let company_file1 = CompanyFile{
        ciphered_content: company_file1_content_ciphered.0,
        content_nonce: company_file1_content_ciphered.1.to_vec(),
        ciphered_filename: company_file1_name_ciphered.0,
        filename_nonce: company_file1_name_ciphered.1.to_vec(),
        salt: file_hash1_parts.1.to_vec()
    };

    let company_file2 = CompanyFile{
        ciphered_content: file_content2_ciphered.0,
        content_nonce: file_content2_ciphered.1.to_vec(),
        ciphered_filename: file_name2_ciphered.0,
        filename_nonce: file_name2_ciphered.1.to_vec(),
        salt: file_hash2_parts.1.to_vec()
    };

    let company_file3 = CompanyFile{
        ciphered_content: file_content3_ciphered.0,
        content_nonce: file_content3_ciphered.1.to_vec(),
        ciphered_filename: file_name3_ciphered.0,
        filename_nonce: file_name3_ciphered.1.to_vec(),
        salt: file_hash3_parts.1.to_vec()
    };

    // Create a magic table to store the company files name ciphered
    let magic_table_ciphered_company_filename = vec![company_file1.ciphered_filename.clone(), company_file2.ciphered_filename.clone(), company_file3.ciphered_filename.clone()];
    let magic_table_company_filename_nonce = vec![company_file1.filename_nonce.clone(), company_file2.filename_nonce.clone(), company_file3.filename_nonce.clone()];

    let mut data_company_magic_table = HashMap::new();
    data_company_magic_table.insert(
        0,
        MagicTable{
            list_of_ciphered_company_filename: magic_table_ciphered_company_filename,
            list_of_company_filename_nonce: magic_table_company_filename_nonce,
        },
    );

    // Write the magic table in a json file
    let json_string = serde_json::to_string(&data_company_magic_table).unwrap();
    let mut file = File::create("magic_table.json").unwrap();
    file.write_all(json_string.as_bytes()).unwrap();
    println!("[INFO Server log] Magic table created for the company : ACME");

    let mut data_company_file = HashMap::new();
    data_company_file.insert(
        0,
        company_file1,
    );

    data_company_file.insert(
        1,
        company_file2,
    );

    data_company_file.insert(
        2,
        company_file3,
    );

    // Write the company files in a json file
    let json_company_file = serde_json::to_string(&data_company_file).unwrap();
    let mut file = File::create("company_files.json").unwrap();
    file.write_all(json_company_file.as_bytes()).unwrap();
    println!("[INFO Server log] 3 company files created for the company : ACME");

    let mut data_company = HashMap::new();
    data_company.insert(
        0,
        Company{
            name: "ACME".to_string(),
            public_key: keypair.public_key.to_vec(),
            ciphered_master_key: master_key_256_ciphered.0,
            master_key_nonce: private_key_256_ciphered.1.to_vec(),
            ciphered_private_key: private_key_256_ciphered.0,
            private_key_nonce: master_key_256_ciphered.1.to_vec(),
            users: vec![user1, user2, user3, user4],
            magic_table_index: 0,
        },
    );

    // Convert the HashMap to a JSON string.
    let json_string = serde_json::to_string(&data_company).unwrap();
    // Write the JSON string to a file.
    let mut file = File::create("db_server.json").unwrap();
    file.write_all(json_string.as_bytes()).unwrap();

    println!("[INFO Server log] Database (db_server.json) created and initialized with 1 company (ACME) and 4 users");
}