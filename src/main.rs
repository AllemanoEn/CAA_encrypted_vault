#![allow(non_snake_case)]
extern crate core;

mod ressources;
mod init;

use init::init_server_architecture;
use ressources::{recover_a_shard_if_user_exists, aes256gcm_decrypt, Company, MagicTable, CompanyFile};

use std::{collections::HashMap,env,fs::File,io,io::{Read,prelude::*}};

use aes_gcm::{
    aead::{KeyInit,OsRng,
           consts::U32,
           generic_array::GenericArray},
    Aes256Gcm};

use dryoc::{dryocbox::*,pwhash::*};

use shamir::SecretData;

// Temporary server DB only known by the server
static mut TOKEN_CHALLENGE: Vec<u8> = Vec::new();

fn main() {

    let args: Vec<String> = env::args().collect();

    let count_args = args.len();

    if count_args != 2 {
        println!("Usage : cargo run <mode>");
        println!("mode : <1> to init the server architecture and <2> to start the client");
        return;
    }

    let mut answer = String::new();
    answer.push_str("n");

    // if the args is 1, we init the server architecture
    if args[1] == "1" {
        println!("[INFO Server log] Init the server architecture");
        init_server_architecture();

        // Ask the user if he wants to start the server
        println!();
        print!("Do you want to start the client ? (y/n) : ");
        io::stdout().flush().unwrap();
        answer.clear();
        io::stdin().read_line(&mut answer).expect("Failed to read line");
    }

    // if the args is 2 or if the user wants to start the server, we start the server
    if (args[1] == "2") || (answer.trim() == "y") {
        println!("[INFO log] Starting the client");
        unsafe { start_client(); }

    } else if answer.trim() == "n" {
        println!("[INFO Server log] Server stopped");
    } else {
        panic!("Incorrect argument");
    }

}

unsafe fn start_client() {
    println!();

    // Ask the user to enter the name of the company
    print!("Enter the name of the company : ");
    io::stdout().flush().unwrap();
    let mut company_name = String::new();
    io::stdin().read_line(&mut company_name).expect("Failed to read line");
    company_name = company_name.trim().to_string();

    // Ask the user to enter two users with their name and their password
    println!("Provide the username (u) and the password (p) of two user : ");
    println!();
    println!("User 1");
    print!("u: ");
    io::stdout().flush().unwrap();
    let mut user1_name = String::new();
    io::stdin().read_line(&mut user1_name).expect("Failed to read line");
    user1_name = user1_name.trim().to_string();

    let binding = rpassword::prompt_password("p (hidden): ").unwrap();
    let user1_password = binding.as_bytes();

    println!();

    println!("User 2");
    print!("u: ");
    io::stdout().flush().unwrap();
    let mut user2_name = String::new();
    io::stdin().read_line(&mut user2_name).expect("Failed to read line");
    user2_name = user2_name.trim().to_string();

    let binding = rpassword::prompt_password("p (hidden): ").unwrap();
    let user2_password = binding.as_bytes();

    println!();

    println!("[INFO log] Start the authentication process between the client and the server");
    println!("[INFO log] Client ask the server to generate a challenge");
    println!();

    // Ask the server to send the challenge and the company
    let (challenge, company) = ask_server_challenge(&company_name);

    println!("[INFO log] Client start recovering all the company key");

    let mut clear_shard_vec: Vec<Vec<u8>> = vec![];

    // Recover the shard of the first user
    let clear_shard1 = recover_a_shard_if_user_exists(&company, &user1_name, &user1_password.to_vec());
    clear_shard_vec.push(clear_shard1);

    // Recover the shard of the second user
    let clear_shard2 = recover_a_shard_if_user_exists(&company, &user2_name, &user2_password.to_vec());
    clear_shard_vec.push(clear_shard2);

    // Recover the intermediate key with the two recovered shards
    let recovered_intermediate_key = SecretData::recover_secret(2, clear_shard_vec).unwrap();

    let mut recovered_intermediate_key_bytes = GenericArray::<u8, U32>::default();
    recovered_intermediate_key_bytes.copy_from_slice(base64::decode(&recovered_intermediate_key).unwrap().as_slice());

    println!("[INFO log] The intermediate key has been recovered");

    let master_key_nonce_bytes = company.master_key_nonce.as_slice();
    let ciphered_master_key = company.ciphered_master_key.as_slice();
    // Decypher the master key with the recovered intermediate key
    let recovered_master_key = aes256gcm_decrypt(&recovered_intermediate_key_bytes, master_key_nonce_bytes, &ciphered_master_key);

    println!("[INFO log] The master key has been recovered");

    let mut recovered_master_key_bytes = GenericArray::default();
    recovered_master_key_bytes.copy_from_slice(&recovered_master_key.as_slice());

    let private_key_nonce_bytes = company.private_key_nonce.as_slice();
    let ciphered_private_key = company.ciphered_private_key.as_slice();
    // Decypher the private key with the master key
    let recovered_private_key = aes256gcm_decrypt(&recovered_master_key_bytes, private_key_nonce_bytes, &ciphered_private_key);

    println!("[INFO log] The private key has been recovered");

    // Decypher the token with the private key
    let mut recovered_private_key_bytes = GenericArray::<u8, U32>::default();
    recovered_private_key_bytes.copy_from_slice(&recovered_private_key.as_slice());

    let company_key_pair = KeyPair::from_slices(&company.public_key.as_slice(), &recovered_private_key_bytes.as_slice()).unwrap();

    let recovered_token = challenge.unseal_to_vec(&company_key_pair).unwrap();

    // Ask the server if the token is correct
    ask_server_to_verify_challenge(&recovered_token);

    println!();
    println!("[INFO log] The challenge has been verified by the server");
    println!();

    println!("[INFO log] The client is now authenticated");
    println!("[INFO log] The client can now ask for the magic table");
    println!();

    // Ask the server for the magic table
    let magic_table = ask_server_for_company_magic_table(&company.magic_table_index);

    println!("Available company files stored in the server :");

    // Decypher the content of the magic table with the master key
    for i in 0..magic_table.list_of_ciphered_company_filename.len() {
        let filename = aes256gcm_decrypt(&recovered_master_key_bytes, &magic_table.list_of_company_filename_nonce[i].as_slice(), &magic_table.list_of_ciphered_company_filename[i].as_slice());

        // Convert the filename from bytes to string
        let filename_string = String::from_utf8(filename).unwrap();
        println!("{}) {}",i+1, filename_string);
    }


    // loop to ask the user to select a file
    loop {
        print!("Select a file from the list above by selecting the corresponding index (0 to shutdown the client) : ");
        io::stdout().flush().unwrap();

        let mut selected_file_index = String::new();
        io::stdin().read_line(&mut selected_file_index).expect("Failed to read line");
        selected_file_index = selected_file_index.trim().to_string();

        // Convert the index from string to u32
        let selected_file_index: u32 = selected_file_index.parse().unwrap();

        if selected_file_index == 0 {
            println!("[INFO log] The client is shutting down");
            break;
        }

        // Ask the server for the specific file
        let file = ask_server_for_company_file(&magic_table.list_of_ciphered_company_filename[selected_file_index as usize - 1]);

        // Decypher the content of the file with the Argon2 key (PwHash)
        // We first recover the Argon2 key by concatenating the clear company filename and the master key
        let clear_company_file_name = aes256gcm_decrypt(&recovered_master_key_bytes, &file.filename_nonce, &file.ciphered_filename);

        let master_and_company_file_name = [clear_company_file_name.as_slice(), recovered_master_key_bytes.as_slice()].concat();
        let argon2_key: &Vec<u8> = master_and_company_file_name.as_ref();

        let pwhash: VecPwHash = PwHash::hash_with_salt(
            argon2_key,
            file.salt,
            Config::interactive().with_salt_length(16).with_hash_length(32).with_opslimit(2).with_memlimit(67108864),
        ).expect("unable to hash password1 with salt and custom config");

        // Convert the hash to generic array to be able to use it in the cipher
        let mut hash = GenericArray::default();
        let hash_parts = pwhash.into_parts();
        hash.copy_from_slice(hash_parts.0.as_slice());

        // Decypher the content of the file with aes256gcm
        let file_content = aes256gcm_decrypt(&hash, &file.content_nonce, &file.ciphered_content);

        // Convert the file content from bytes to string
        let file_content_string = String::from_utf8(file_content).unwrap();

        println!();
        println!("Content of {}:", String::from_utf8(clear_company_file_name).unwrap());
        println!("{}", file_content_string);
        println!();
    }
}

fn ask_server_for_company_file(ciphered_company_filename: &Vec<u8>) -> CompanyFile {
    // Read the JSON file
    let mut file = File::open("company_files.json").expect("File not found");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Something went wrong reading the file");

    // Parse the JSON file
    let data: HashMap<u8,CompanyFile> = serde_json::from_str(&contents).unwrap();

    // Search for the file that has the same ciphered filename as the one we are looking for
    for (_, company_file) in data {
        if company_file.ciphered_filename == *ciphered_company_filename {
            return CompanyFile {
                ciphered_filename: company_file.ciphered_filename,
                filename_nonce: company_file.filename_nonce,
                salt: company_file.salt,
                ciphered_content: company_file.ciphered_content,
                content_nonce: company_file.content_nonce,
            };
        }
    }

    panic!("The file has not been found");
}

fn ask_server_for_company_magic_table(index: &u8) -> MagicTable {
    // Read the JSON string from the file
    let mut file = File::open("magic_table.json").expect("File not found");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Something went wrong reading the file");

    // Convert the JSON string to a MagicTable struct
    let data: HashMap<u8, MagicTable> = serde_json::from_str(&contents).unwrap();
    let magic_table = data.get(index).unwrap();

    // copy the magic table to a new struct an return it
    MagicTable {
        list_of_ciphered_company_filename: magic_table.list_of_ciphered_company_filename.clone(),
        list_of_company_filename_nonce: magic_table.list_of_company_filename_nonce.clone(),
    }
}

unsafe fn ask_server_to_verify_challenge(token: &[u8]) {
    if token != TOKEN_CHALLENGE {
        panic!("The client the failed to solve the challenge");
    }

    // Clear the token
    TOKEN_CHALLENGE.clear();
}

unsafe fn ask_server_challenge(compagny_name : &str) -> (DryocBox<PublicKey, Mac, Vec<u8>>, Company) {
    // Read the JSON string from the file.
    let mut file = File::open("db_server.json").unwrap();
    let mut json_string = String::new();
    file.read_to_string(&mut json_string).expect("Something went wrong reading the file");

    // Convert the JSON string to Company struct
    let data: HashMap<u32, Company> = serde_json::from_str(&json_string).unwrap();

    for (_, company) in data  {
        if company.name == compagny_name {
            // copy the company from the json file in a new company
            let cloned_company = Company {
                name: company.name.clone(),
                public_key: company.public_key.clone(),
                ciphered_master_key: company.ciphered_master_key.clone(),
                master_key_nonce: company.master_key_nonce.clone(),
                ciphered_private_key: company.ciphered_private_key.clone(),
                private_key_nonce: company.private_key_nonce.clone(),
                users: company.users.clone(),
                magic_table_index: company.magic_table_index.clone(),
            };

            // Generate a random token
            let token = Aes256Gcm::generate_key(&mut OsRng);
            let token_byte = token.as_slice();
            TOKEN_CHALLENGE = token_byte.to_vec();

            let ciphered_token = DryocBox::seal_to_vecbox(token_byte, &company.public_key.as_slice().try_into().unwrap())
                .expect("unable to seal");

            return (ciphered_token, cloned_company);
        }
    }

    panic!("This company does not exist");
}
