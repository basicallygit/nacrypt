use anyhow::{Context, Result, bail};
use clap::Parser;
use libsodium_rs as sodium;
use rpassword::prompt_password;
use sodium::crypto_box;
use std::fs::{File, metadata};
use std::io::Seek;
use std::path::PathBuf;

use nacrypt::crypto::asymmetric;
use nacrypt::crypto::consts::{MAX_NUM_RECIPIENTS, NACRYPT_SECRET_KEY_PATH, SYMMETRY_ASYMMETRIC};
use nacrypt::crypto::helpers::{
    dearmor_public_key, generate_keypair, memzero_string, read_secret_key, regenerate_public_key,
};
use nacrypt::crypto::symmetric;
use nacrypt::header::NacryptHeader;
use nacrypt::utils;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None, long_version = concat!(
    "version ",
    env!("CARGO_PKG_VERSION"),
    "\nCopyright (C) 2026 basicallygit (Apache-2.0 License)"
))]
struct Args {
    /// The input file
    #[arg(required_unless_present_any = ["gen_key", "regen_public"])]
    input: Option<PathBuf>,

    /// File to output to
    #[arg(short, long, requires = "input", required_unless_present_any = ["gen_key", "regen_public"])]
    output: Option<PathBuf>,

    /// [optional] Specify encrypt mode
    #[arg(short, long, requires = "input")]
    encrypt: bool,

    /// [optional] Specify decrypt mode
    #[arg(short, long, requires = "input")]
    decrypt: bool,

    /// Generate a new keypair
    #[arg(short, long, conflicts_with_all = ["input", "output", "decrypt", "encrypt", "recipients", "regen_public"])]
    gen_key: bool,

    /// Regenerate your public key if it was lost
    #[arg(short = 'R', long, conflicts_with_all = ["input", "output", "decrypt", "encrypt", "recipients", "gen_key"])]
    regen_public: bool,

    /// Encrypt this file to recipient's public key
    #[arg(short = 'r', long = "recipient")]
    recipients: Vec<String>,

    /// Specify custom path to private key to use
    #[arg(short = 'p', long = "private-key")]
    secret_key_path: Option<PathBuf>,

    /// Display verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
    Unspecified,
}

fn main() -> Result<()> {
    let args = Args::parse();
    sodium::ensure_init().context("Failed to initialize libsodium")?;

    // Exclusive arguments
    if args.gen_key {
        generate_keypair()?;
        return Ok(());
    } else if args.regen_public {
        regenerate_public_key(args.secret_key_path)?;
        return Ok(());
    }

    let input = args.input.as_ref().unwrap();
    let output = args.output.as_ref().unwrap();

    let mut input_file =
        File::open(&input).with_context(|| format!("Failed to open {}", input.display()))?;

    if output.exists() {
        if metadata(&output)?.len() != 0 {
            bail!("{} Already exists and is not empty", output.display());
        }
    }

    // Create or truncate
    let mut output_file = File::create(&output)?;

    let num_recipients = args.recipients.len();
    if num_recipients > MAX_NUM_RECIPIENTS.into() {
        bail!("Too many recipients specified (max {})", MAX_NUM_RECIPIENTS);
    }

    let mut mode = Mode::Unspecified;

    if args.encrypt {
        mode = Mode::Encrypt;
    } else if args.decrypt {
        mode = Mode::Decrypt;
    }

    if mode == Mode::Unspecified {
        // Try to figure out the mode wanted
        if NacryptHeader::read_header(&mut input_file).is_ok() {
            // Valid nacrypt file, assume decrypt
            mode = Mode::Decrypt;
        } else {
            // No valid nacrypt header found, assume encrypt
            mode = Mode::Encrypt;
        }
        input_file.rewind()?;
    }

    if mode == Mode::Encrypt {
        if num_recipients != 0 {
            // Asymmetric encrypt mode
            let mut recipient_pubkeys: Vec<crypto_box::PublicKey> = Vec::new();
            for armored_pubkey in args.recipients {
                recipient_pubkeys.push(dearmor_public_key(armored_pubkey)?);
            }
            asymmetric::encrypt(&mut input_file, &mut output_file, &recipient_pubkeys)?;
            return Ok(());
        } else {
            // Symmetric encrypt mode
            let password = prompt_password("Please create a password: ").unwrap();
            {
                let password_again = prompt_password("Please re-enter the password: ").unwrap();
                if !sodium::utils::memcmp(password.as_bytes(), password_again.as_bytes()) {
                    bail!("Passwords did not match!");
                }
                memzero_string(password_again);
            }
            symmetric::encrypt(&mut input_file, &mut output_file, password)?;
            return Ok(());
        }
    } else {
        let header = NacryptHeader::read_header(&mut input_file)?;
        input_file.rewind()?;

        if header.symmetry_type == SYMMETRY_ASYMMETRIC {
            // Asymmetric decrypt mode
            let default_secret_key_path = utils::expand_tilde(NACRYPT_SECRET_KEY_PATH)?;
            let secret_key_path = match args.secret_key_path {
                Some(ref path) => path,
                None => &PathBuf::from(&default_secret_key_path),
            };

            let mut secret_key_file = File::open(secret_key_path)?;

            let password = prompt_password(format!(
                "Enter password for {}: ",
                secret_key_path.display()
            ))
            .unwrap();
            let secret_key = read_secret_key(&mut secret_key_file, password)?;

            asymmetric::decrypt(&mut input_file, &mut output_file, &secret_key)?;
            return Ok(());
        } else {
            // Symmetric decrypt mode
            let password =
                prompt_password(format!("Enter password for {}: ", input.display())).unwrap();
            symmetric::decrypt(&mut input_file, &mut output_file, password)?;
            return Ok(());
        }
    }
}
