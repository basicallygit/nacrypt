use anyhow::Result;
use clap::Parser;
use libsodium_rs as sodium;
use nacrypt::crypto::consts::{NACRYPT_CHUNK_SIZE, SALT_LEN};
use sodium::crypto_box::SEALBYTES;
use sodium::crypto_secretstream::xchacha20poly1305::{ABYTES, HEADERBYTES, KEYBYTES};
use std::fs::metadata;
use std::path::PathBuf;

const NACRYPT_HEADER_OVERHEAD: usize = 6 + HEADERBYTES; // magic[u8; 4] + version: u8 + symmetry: u8 + secretstream header
const SYMMETRIC_HEADER_OVERHEAD: usize = 8 + SALT_LEN; // opslimit: u32 + memlimit: u32 + salt[u8; SALT_LEN]
const ASYMMETRIC_HEADER_OVERHEAD: usize = 1; // num_recipients: u8
const RECIPIENT_OVERHEAD: usize = KEYBYTES + SEALBYTES; // symmetric key inside a crypto_box

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    input: PathBuf,

    #[arg(short, long)]
    recipients: Option<u8>,
}

const KIB: f64 = 1024.0;
const MIB: f64 = KIB * 1024.0;
const GIB: f64 = MIB * 1024.0;

fn human_readable(value: usize) -> String {
    let value = value as f64;
    if value >= GIB {
        format!("{:.2} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.2} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.2} KiB", value / KIB)
    } else {
        format!("{} Bytes", value)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let file_size: usize = metadata(&args.input)?.len().try_into()?;
    let mut overhead: usize = NACRYPT_HEADER_OVERHEAD;
    let num_chunks = file_size / NACRYPT_CHUNK_SIZE;
    let remainder = file_size % NACRYPT_CHUNK_SIZE;

    overhead += num_chunks * ABYTES;
    if remainder != 0 {
        overhead += ABYTES;
    }

    if num_chunks == 0 && remainder == 0 {
        // Empty file
        overhead += ABYTES;
    }

    if args.recipients.is_some() {
        overhead += ASYMMETRIC_HEADER_OVERHEAD;
        overhead += args.recipients.unwrap() as usize * RECIPIENT_OVERHEAD;
    } else {
        overhead += SYMMETRIC_HEADER_OVERHEAD;
    }

    println!("{}:", args.input.display());
    println!(" Size before encryption: {}", human_readable(file_size));
    println!(
        " Encryption mode: {}",
        if args.recipients.is_some() {
            "asymmetric"
        } else {
            "symmetric"
        }
    );
    println!(" Encryption overhead: {}", human_readable(overhead));
    println!(
        " Final size after encryption: {}",
        human_readable(overhead + file_size)
    );
    Ok(())
}
