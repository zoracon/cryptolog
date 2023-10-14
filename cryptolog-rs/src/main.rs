pub mod bsixtyfour;

use clap::Parser;
use regex::{Regex};
use thiserror::Error;
use anyhow::{Context, Result};
use std::io::{BufReader, BufRead, Write};
use std::str;
use std::fs;
use std::fs::File;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use rand::{Rng, thread_rng};
use crate::bsixtyfour::b64_vec_encode;

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

// Creates new HMAC digest with salt
fn hash(entity: &[u8], hashed_size: usize, salt_param: Option<&[u8]>) -> String {
    let salt_var = salt_param.unwrap_or_else(|| &salt());
    let mut mac = HmacSha256::new_from_slice(&salt_var).expect("HMAC initialization failed");
    mac.update(entity);
    let digest = mac.finalize().into_bytes();
    let finalhash = &b64_vec_encode(&digest)[..hashed_size];
    return str::from_utf8(&finalhash).unwrap().to_string();
}

/// A program to encrypt the IP addresses in web server logs, to be used within an Apache CustomLog line
#[derive(Parser, Debug)]
#[command(author = "zoonarc", version, about, long_about = None)]
struct Args {
    /// Filename to write logs to
    #[arg(short, long)]
    write: String,

    /// Comma-separated list of entities to filter
    #[arg(short, long)]
    log: String,
}

fn main() -> Result<()> {
    let entities = Args::parse();
    let log_path = entities.log;
    let new_file = entities.write;

    println!("Using log file: {:?}", log_path);
    let buffered = BufReader::new(File::open(log_path)?);

    // The regex \b is used to ensure that the matching sequence is a whole word (to avoid partial matches), and it alternates between matching IPv4 and IPv6 addresses. 
    // This regex will match IPv4 addresses in standard dotted-decimal notation and IPv6 addresses in their hexadecimal format.
    println!("Parsing and Encrypting IPs in log file");
    // let set = Regex::new(r#"\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)\b"#).unwrap();
    let set = Regex::new(r#"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#,).unwrap();


    // Stream log file and replace IP in each log entry.
    let data: Vec<String> = buffered
            .lines()
            .filter_map(|line| line.ok())
            // encrypt each log entry
            .map(|line| set.replace_all(&line, &hash(line.as_bytes(), 8, None)).to_string())
            .collect();

    // Create new log file
    println!("Creating new log file");
    let mut file = File::create(new_file)?;

    // Write the data to the file
    for line in &data {
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?; // Add a newline after each line
        file.flush()?;
    }

    println!("Finishing up...");
    Ok(())
}
