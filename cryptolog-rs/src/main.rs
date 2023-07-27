pub mod bsixtyfour;
use clap::{Arg, Command};
use thiserror::Error;
use anyhow::{Context, Result};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use rand::prelude::*;
use rand::{Rng, thread_rng};
use chrono::prelude::*;

// use crate::bsixtyfour::b64_general_encode;
use base64::encode;
use crate::bsixtyfour::b64_general_encode;
type HmacSha256 = Hmac<Sha256>;

const SALT_SIZE: usize = 16;

lazy_static::lazy_static! {
    static ref SALT: Vec<u8> = urandom(SALT_SIZE);
}

fn urandom(size: usize) -> Vec<u8> {
    // TODO: Implement the urandom function to generate random bytes
    let mut rng = thread_rng();
    (0..size).map(|_| rng.gen::<u8>()).collect()
}

fn salt() -> &'static [u8] {
    &SALT
}

pub fn hash(entity: &[u8], hashed_size: usize, salt_param: Option<&[u8]>) -> String {
    let size: usize = 16;
    let salt_var = salt_param.unwrap_or_else(|| &salt());
    let mut mac = HmacSha256::new_from_slice(&salt_var).expect("HMAC initialization failed");
    mac.update(entity);
    let digest = mac.finalize().into_bytes();
    return encode(&digest)[..hashed_size].to_string();
}

fn main() {
    let log_entry = b"127.0.0.1";
    // println!("{:?}", salt(SALT_SIZE));

    let hashed_size = 16;
    let salt_param = salt();
    let hashed = hash(log_entry, hashed_size, None);

    // let hashed = hash(log_entry, 6, salt);
    println!("{:?}", hashed);
}




