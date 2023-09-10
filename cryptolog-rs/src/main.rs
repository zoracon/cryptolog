use clap::Parser;
use regex::{Regex, RegexSetBuilder};
use thiserror::Error;
// use anyhow::{Context, Result};
use std::io::{BufReader, BufRead, Write};
use std::str;
use std::fs::File;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use rand::{Rng, thread_rng};
use base64::{Engine as _, engine::general_purpose};
use error_chain::error_chain;

// Temporary error handling
error_chain! {
    foreign_links {
        Io(std::io::Error);
        Regex(regex::Error);
    }
}

type HmacSha256 = Hmac<Sha256>;

const SALT_SIZE: usize = 16;

// There's got to be a better way to generate a salt, but doing this for now
lazy_static::lazy_static! {
    static ref SALT: Vec<u8> = urandom(SALT_SIZE);
}

fn urandom(size: usize) -> Vec<u8> {
    // thread-local generator
    let mut rng = thread_rng();

    (0..size).map(|_| rng.gen::<u8>()).collect()
}

fn salt() -> &'static [u8] {
    &SALT
}

// Original base64::encode is deprecated. Must reimplement with provided general engine
// Encode_slice
fn b64_encode(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    //TODO: explain
    buf.resize(data.len() * 4 / 3 + 4, 0);
    //TODO: handle unwraps with proper error handling
    let bytes_written = general_purpose::STANDARD.encode_slice(data, &mut buf).unwrap();
    buf.truncate(bytes_written);
    return buf;
}

// Creates new HMAC digest with salt
fn hash(entity: &[u8], hashed_size: usize, salt_param: Option<&[u8]>) -> String {
    //TODO: handle unwraps with proper error handling
    let salt_var = salt_param.unwrap_or_else(|| &salt());
    let mut mac = HmacSha256::new_from_slice(&salt_var).expect("HMAC initialization failed");
    mac.update(entity);
    let digest = mac.finalize().into_bytes();
    let finalhash = &b64_encode(&digest)[..hashed_size];
    //TODO: handle unwraps with proper error handling
    return str::from_utf8(&finalhash).unwrap().to_string();
}

/// A program to encrypt the IP addresses in web server logs, to be used within an Apache CustomLog line
#[derive(Parser, Debug)]
#[command(author = "zoonarc", version, about, long_about = None)]
struct Args {
    /// Filename to write logs to
    // #[arg(short, long, default_value="")]
    // write: String,

    /// Comma-separated list of entities to filter
    #[arg(short, long)]
    log: String,
}

fn main() -> Result<()> {
    //DEBUG println!("{:?}", salt(SALT_SIZE));
    let entities = Args::parse();
    let log_path = entities.log;

    println!("Using: {:?}", log_path);
    
    let buffered = BufReader::new(File::open(log_path)?);

    // TODO: Incorporate IPV6
    let set = Regex::new(
        r#"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#,).unwrap();

    let data: Vec<String> = buffered
            .lines()
            .filter_map(|line| line.ok())
            // encrypt each log entry
            .map(|line| set.replace_all(&line, &hash(line.as_bytes(), 6, None)).to_string())
            .collect();

    // Create crypto log file
    let file_path = "crypto_log.txt";
    let mut file = File::create(file_path)?;

    // Write the data to the file
    for line in &data {
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?; // Add a newline after each line
    }

    // DEBUG .for_each(|x| println!("{}", x)); 

    Ok(())
}
