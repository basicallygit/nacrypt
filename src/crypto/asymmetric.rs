use crate::crypto::consts::SYMMETRY_ASYMMETRIC;
use crate::crypto::generic;
use crate::header::{AsymmetricHeader, NacryptHeader};
use anyhow::{Result, bail};
use libsodium_rs as sodium;
use sodium::crypto_box;
use sodium::crypto_scalarmult::curve25519;
use sodium::crypto_secretstream::xchacha20poly1305;
use std::io::{Read, Write};

pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    recipients: &Vec<crypto_box::PublicKey>,
) -> Result<()> {
    let num_recipients = recipients.len() as u8;
    // Sanity check
    if num_recipients == 0 {
        bail!("No recipients");
    }

    let header = NacryptHeader::new(SYMMETRY_ASYMMETRIC);
    header.write_header(output)?;

    let asymm_header = AsymmetricHeader::new(num_recipients);
    asymm_header.write_header(output)?;

    let key = xchacha20poly1305::Key::generate();

    // Wrap the key inside a crypto_box for each recipient
    for recipient_pubkey in recipients {
        let sealed_box = crypto_box::seal_box(key.as_bytes(), &recipient_pubkey)?;
        output.write_all(&sealed_box)?;
    }

    generic::encrypt(input, output, &key)?;

    Ok(())
}

pub fn decrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    secret_key: &crypto_box::SecretKey,
) -> Result<()> {
    let header = NacryptHeader::read_header(input)?;
    if header.symmetry_type != SYMMETRY_ASYMMETRIC {
        bail!("Expected asymmetric type, got symmetric");
    }
    let asymm_header = AsymmetricHeader::read_header(input)?;

    // Get the public key back from the private key, needed to open sealed box
    let public_key =
        crypto_box::PublicKey::from_bytes(&curve25519::scalarmult_base(secret_key.as_bytes())?)?;

    let file_key_maybe: Option<xchacha20poly1305::Key> = {
        let mut sealed_box_buf = [0u8; xchacha20poly1305::KEYBYTES + crypto_box::SEALBYTES];
        let mut found_key = None;

        for _ in 0..asymm_header.num_recipients {
            input.read_exact(&mut sealed_box_buf)?;

            if found_key.is_some() {
                continue;
            }

            match crypto_box::open_sealed_box(&sealed_box_buf, &public_key, &secret_key) {
                Ok(file_key_bytes) => {
                    found_key = Some(xchacha20poly1305::Key::from_bytes(&file_key_bytes)?);
                }
                _ => {} // Not for us
            }
        }

        found_key
    };

    let Some(file_key) = file_key_maybe else {
        bail!("No openable sealed boxes found, either corrupted file or you are not a recipient");
    };

    generic::decrypt(input, output, &file_key)?;

    Ok(())
}
