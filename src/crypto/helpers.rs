use crate::crypto::consts::{
    NACRYPT_DIRECTORY, NACRYPT_KDF_ALG_DEFAULT, NACRYPT_MEMLIMIT_DEFAULT, NACRYPT_OPSLIMIT_DEFAULT,
    NACRYPT_PUBKEY_PREFIX, NACRYPT_PUBLIC_KEY_PATH, NACRYPT_SECRET_KEY_PATH, SALT_LEN,
};
use crate::header::SecretKeyHeader;
use crate::utils;
use anyhow::{Context, Result, bail};
use libsodium_rs as sodium;
use rpassword::prompt_password;
use sodium::crypto_box;
use sodium::crypto_scalarmult::curve25519;
use sodium::crypto_secretbox;
use std::fs::{File, create_dir, metadata};
use std::io::{Read, Write, stdout};
use std::path::Path;

pub fn derive_key(
    out_len: usize,
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
) -> Result<Vec<u8>> {
    print!("Deriving key from password.. ");
    let _ = stdout().flush();
    let result = sodium::crypto_pwhash::pwhash(
        out_len,
        password,
        salt,
        opslimit,
        memlimit,
        NACRYPT_KDF_ALG_DEFAULT,
    )?;
    println!("done");
    Ok(result)
}

pub fn memzero_string(mut string: String) {
    // SAFETY: memzero overwrites the buffer with null bytes (0x00).
    // A sequence of null bytes is valid UTF-8, and the string itself
    // gets taken ownership of by this function and dropped after, so
    // it cannot be used after this function ends anyway.
    unsafe {
        let bytes = string.as_bytes_mut();
        sodium::utils::memzero(bytes);
    }
}

pub fn armor_public_key(public_key: &crypto_box::PublicKey) -> String {
    let b64 = sodium::utils::bin2base64(
        public_key.as_bytes(),
        sodium::utils::BASE64_VARIANT_ORIGINAL,
    );
    format!("{}{}", NACRYPT_PUBKEY_PREFIX, b64)
}

pub fn dearmor_public_key(armored_pubkey: String) -> Result<crypto_box::PublicKey> {
    if armored_pubkey.len() + 1
        != NACRYPT_PUBKEY_PREFIX.len()
            + sodium::utils::base64_encoded_len(
                crypto_box::PUBLICKEYBYTES,
                sodium::utils::BASE64_VARIANT_ORIGINAL,
            )
        || !armored_pubkey.starts_with(NACRYPT_PUBKEY_PREFIX)
    {
        eprintln!("{}", armored_pubkey.len());
        eprintln!(
            "{}",
            NACRYPT_PUBKEY_PREFIX.len()
                + sodium::utils::base64_encoded_len(
                    crypto_box::PUBLICKEYBYTES,
                    sodium::utils::BASE64_VARIANT_ORIGINAL,
                )
        );
        bail!("FATAL: Not a valid nacrypt public key");
    }

    let pubkey = sodium::utils::base642bin(
        armored_pubkey.strip_prefix(NACRYPT_PUBKEY_PREFIX).unwrap(),
        sodium::utils::BASE64_VARIANT_ORIGINAL,
    )
    .context("FATAL: Invalid nacrypt public key base64 data")?;

    let pubkey_arr: [u8; crypto_box::PUBLICKEYBYTES] = pubkey.try_into().unwrap();
    Ok(crypto_box::PublicKey::from_bytes(&pubkey_arr)?)
}

pub fn generate_keypair() -> Result<()> {
    let keypair = crypto_box::KeyPair::generate();

    let nacrypt_dir = utils::expand_tilde(NACRYPT_DIRECTORY)?;
    let public_key_path = utils::expand_tilde(NACRYPT_PUBLIC_KEY_PATH)?;
    let secret_key_path = utils::expand_tilde(NACRYPT_SECRET_KEY_PATH)?;

    if !Path::new(&nacrypt_dir).exists() {
        create_dir(&nacrypt_dir)?;
        println!("[INFO] Created directory {}", nacrypt_dir);
    }

    if Path::new(&secret_key_path).exists() {
        if metadata(&secret_key_path)?.len() != 0 {
            bail!("{} Already exists and is not empty!", secret_key_path);
        }
    }

    let password =
        prompt_password("Please create a password to protect your private key on disk: ").unwrap();
    {
        let password_again = prompt_password("Please re-enter the password: ").unwrap();
        if !sodium::utils::memcmp(password.as_bytes(), password_again.as_bytes()) {
            bail!("Passwords did not match!");
        }
        memzero_string(password_again);
    }

    let mut secret_key_file = File::create(&secret_key_path)?;
    write_secret_key(&mut secret_key_file, keypair.secret_key, password)?;

    let mut public_key_file = File::create(&public_key_path)?;
    write_public_key(&mut public_key_file, &keypair.public_key)?;

    let armored_pubkey = armor_public_key(&keypair.public_key);
    println!("Your public key: {}", armored_pubkey);

    Ok(())
}

pub fn regenerate_public_key<P: AsRef<Path>>(custom_secret_key_path: Option<P>) -> Result<()> {
    let default_secret_key_path = utils::expand_tilde(NACRYPT_SECRET_KEY_PATH)?;
    let secret_key_path = match custom_secret_key_path {
        Some(ref path) => path.as_ref(),
        None => Path::new(&default_secret_key_path),
    };
    let public_key_path = utils::expand_tilde(NACRYPT_PUBLIC_KEY_PATH)?;

    let mut secret_key_file = File::open(secret_key_path)?;
    let password = prompt_password(format!(
        "Please enter password for {}: ",
        secret_key_path.display()
    ))
    .unwrap();

    let public_key;
    {
        let secret_key = read_secret_key(&mut secret_key_file, password)?;
        public_key = crypto_box::PublicKey::from_bytes(&curve25519::scalarmult_base(
            secret_key.as_bytes(),
        )?)?;
    }

    let armored_pubkey = armor_public_key(&public_key);
    println!("Your public key: {}", armored_pubkey);

    let mut public_key_file = File::create(&public_key_path)?;
    write_public_key(&mut public_key_file, &public_key)?;

    println!("Saved public key to {}", public_key_path);

    Ok(())
}

pub fn write_secret_key<W: Write>(
    output: &mut W,
    secret_key: crypto_box::SecretKey,
    password: String,
) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    sodium::random::fill_bytes(&mut salt);
    let nonce = crypto_secretbox::Nonce::generate();
    let header = SecretKeyHeader::new(
        NACRYPT_OPSLIMIT_DEFAULT as u32,
        NACRYPT_MEMLIMIT_DEFAULT as u32,
        salt,
        nonce,
    );

    header.write_header(output)?;

    let key = crypto_secretbox::Key::from_bytes(&derive_key(
        crypto_secretbox::KEYBYTES,
        password.as_bytes(),
        &header.salt,
        header.opslimit.into(),
        header.memlimit.try_into().unwrap(),
    )?)?;
    memzero_string(password);

    let secretbox = crypto_secretbox::seal(secret_key.as_bytes(), &header.nonce, &key);
    output.write_all(&secretbox)?;

    Ok(())
}

pub fn read_secret_key<R: Read>(input: &mut R, password: String) -> Result<crypto_box::SecretKey> {
    let header = SecretKeyHeader::read_header(input)?;

    let secretbox_key = crypto_secretbox::Key::from_bytes(&derive_key(
        crypto_secretbox::KEYBYTES,
        password.as_bytes(),
        &header.salt,
        header.opslimit.into(),
        header.memlimit.try_into().unwrap(),
    )?)?;
    memzero_string(password);

    let mut secretbox_buf = [0u8; crypto_box::SECRETKEYBYTES + crypto_secretbox::MACBYTES];
    input.read_exact(&mut secretbox_buf)?;

    let secret_key = crypto_box::SecretKey::from_bytes(
        &crypto_secretbox::open(&secretbox_buf, &header.nonce, &secretbox_key)
            .context("Wrong password or corrupted secret key file")?,
    )?;

    Ok(secret_key)
}

pub fn write_public_key<W: Write>(
    output: &mut W,
    public_key: &crypto_box::PublicKey,
) -> Result<()> {
    let mut armored_pubkey = armor_public_key(public_key);
    armored_pubkey.push('\n');
    output.write_all(armored_pubkey.as_bytes())?;

    Ok(())
}
