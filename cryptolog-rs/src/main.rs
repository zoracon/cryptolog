use clap::Parser;
use std::net::Ipv4Addr;

use regex::Regex;
use thiserror::Error;
use anyhow::{Context, Result};
use std::str;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use rand::prelude::*;
use rand::{Rng, thread_rng};
use base64::{Engine as _, engine::general_purpose};
use chrono::prelude::*;

type HmacSha256 = Hmac<Sha256>;

const SALT_SIZE: usize = 16;

// There's got to be a better way to generate a salt, but here we are
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
fn b64_encode(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.resize(data.len() * 4 / 3 + 4, 0);
    //TODO: handle unwraps with error handling
    let bytes_written = general_purpose::STANDARD.encode_slice(data, &mut buf).unwrap();
    buf.truncate(bytes_written);
    return buf;
}

fn hash(entity: &[u8], hashed_size: usize, salt_param: Option<&[u8]>) -> String {
    //TODO: handle unwraps with error handling
    let salt_var = salt_param.unwrap_or_else(|| &salt());
    let mut mac = HmacSha256::new_from_slice(&salt_var).expect("HMAC initialization failed");
    mac.update(entity);
    let digest = mac.finalize().into_bytes();
    let finalhash = &b64_encode(&digest)[..hashed_size];
    //TODO: handle unwraps with error handling
    return str::from_utf8(&finalhash).unwrap().to_string();
}

struct CryptoFilter {
    regex: Regex,
    field_list: Vec<String>,
    delete_list: Vec<String>,
}

/// A program to encrypt the IP addresses in web server logs, to be used within an Apache CustomLog line
#[derive(Parser, Debug)]
#[command(author = "zoonarc", version, about, long_about = None)]
struct Args {
    /// Regex for log format
    #[arg(short, long)]
    regex: String,

    /// Filename to write logs to
    #[arg(short, long, default_value="")]
    write: String,

    /// Comma-separated list of entities to filter
    #[arg(short, long)]
    entities: String,
}

impl CryptoFilter {
    fn new(regex: &str, field_list: Vec<&str>, delete_list: Vec<&str>) -> CryptoFilter {
        CryptoFilter {
            regex: Regex::new(regex).unwrap(),
            field_list: field_list.iter().map(|s| s.to_string()).collect(),
            delete_list: delete_list.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn encrypt_single_log_entry(&self, log_entry: &str) -> Result<String, String> {
        let results = self.regex.captures(log_entry).ok_or("Log format does not match regex.")?;
        let results_dict = results
            .iter()
            // a.iter().map(|s| s.parse()).filter(|s| s.is_ok()).map(|s| s.unwrap());
            .filter_map(|(name, value)| value.map(|v| (name.to_string(), v.as_str().to_string())))
            .collect::<std::collections::HashMap<_, _>>();

        let mut split_log: Vec<_> = results_dict.values().cloned().collect();

        for field in &self.field_list {
            if let Some(res) = results_dict.get(field) {
                let index = split_log.iter().position(|s| s == res).ok_or_else(|| format!("Field '{}' not found in log entry.", field))?;
                split_log[index] = &hash(res.as_bytes(), 6, Some(salt()));
            }
        }

        for field in &self.delete_list {
            if let Some(res) = results_dict.get(field) {
                let index = split_log.iter().position(|s| s == res).ok_or_else(|| format!("Field '{}' not found in log entry.", field))?;
                split_log[index] = "-";
            }
        }

        Ok(split_log.join(" "))
    }

    fn is_initialized(&self) -> bool {
        !self.field_list.is_empty()
    }

    fn reset(&mut self) {
        self.field_list.clear();
    }
}

fn main() {

    let args = Args::parse();
    println!("{:?}", args);

    // let log_entry = b"127.0.0.1 - - [06/Apr/2011:00:00:00 -0700] \"GET /br/br.gif HTTP/1.1\" 301 249 - -";
    // println!("{:?}", salt(SALT_SIZE));
    // let hashed_size = 16;
    // let hashed = hash(log_entry, hashed_size, None);
    // let entities = if args.len() > 1 { args[1].split(',').collect() } else { vec!["IP"] };

    let mut crypto_filter = CryptoFilter::new(r"(?P<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})( )(?P<OTHER>.*)", entities, vec![]);

    let mut log_entry = String::new();
    while stdin.lock().read_line(&mut log_entry).unwrap() > 0 {
        match crypto_filter.encrypt_single_log_entry(&log_entry) {
            Ok(crypted_log) => println!("{}", crypted_log),
            Err(e) => eprintln!("Error: {}", e),
        }
        log_entry.clear();
    }

    // let hashed = hash(log_entry, 6, salt);
    println!("{:?}", hashed);


}




