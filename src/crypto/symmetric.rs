use crate::crypto::consts::{
    NACRYPT_MEMLIMIT_DEFAULT, NACRYPT_OPSLIMIT_DEFAULT, SALT_LEN, SYMMETRY_SYMMETRIC,
};
use crate::crypto::generic;
use crate::crypto::helpers::{derive_key, memzero_string};
use crate::header::{NacryptHeader, SymmetricHeader};
use anyhow::{Result, bail};
use libsodium_rs as sodium;
use sodium::crypto_secretstream::xchacha20poly1305;
use std::io::{Read, Write};

pub fn encrypt<R: Read, W: Write>(input: &mut R, output: &mut W, password: String) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    sodium::random::fill_bytes(&mut salt);

    let header = NacryptHeader::new(SYMMETRY_SYMMETRIC);
    let symm_header = SymmetricHeader::new(
        NACRYPT_OPSLIMIT_DEFAULT as u32,
        NACRYPT_MEMLIMIT_DEFAULT as u32,
        salt,
    );

    let key = xchacha20poly1305::Key::from_bytes(&derive_key(
        xchacha20poly1305::KEYBYTES,
        password.as_bytes(),
        &symm_header.salt,
        symm_header.opslimit.into(),
        symm_header.memlimit.try_into().unwrap(),
    )?)?;

    memzero_string(password);

    header.write_header(output)?;
    symm_header.write_header(output)?;

    generic::encrypt(input, output, &key)?;

    Ok(())
}

pub fn decrypt<R: Read, W: Write>(input: &mut R, output: &mut W, password: String) -> Result<()> {
    let header = NacryptHeader::read_header(input)?;
    if header.symmetry_type != SYMMETRY_SYMMETRIC {
        bail!("Expected symmetric type, got asymmetric");
    }
    let symm_header = SymmetricHeader::read_header(input)?;

    let key = xchacha20poly1305::Key::from_bytes(&derive_key(
        xchacha20poly1305::KEYBYTES,
        password.as_bytes(),
        &symm_header.salt,
        symm_header.opslimit.into(),
        symm_header.memlimit.try_into().unwrap(),
    )?)?;

    memzero_string(password);

    generic::decrypt(input, output, &key)?;

    Ok(())
}
