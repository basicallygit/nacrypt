use anyhow::{Context, Result, bail};
use libsodium_rs as sodium;
use sodium::crypto_secretstream::xchacha20poly1305::{self, TAG_FINAL, TAG_MESSAGE};
use sodium::crypto_secretstream::{Key, PullState, PushState};
use std::io::{Read, Write};

use crate::crypto::consts::NACRYPT_CHUNK_SIZE;

pub fn encrypt<R: Read, W: Write>(input: &mut R, output: &mut W, key: &Key) -> Result<()> {
    let mut buf_in = Box::new([0u8; NACRYPT_CHUNK_SIZE]);
    //let mut buf_out = Box::new([0u8; NACRYPT_CHUNK_SIZE + xchacha20poly1305::ABYTES]);
    let (mut push_state, push_header) = PushState::init_push(key)?;

    output.write_all(&push_header)?;

    loop {
        let rlen = input.read(&mut buf_in[..])?;
        let is_eof = rlen < NACRYPT_CHUNK_SIZE;
        let tag = if is_eof { TAG_FINAL } else { TAG_MESSAGE };

        let encrypted_chunk = push_state.push(&buf_in[..rlen], None, tag)?;

        output.write_all(&encrypted_chunk)?;

        if is_eof {
            break;
        }
    }

    Ok(())
}

pub fn decrypt<R: Read, W: Write>(input: &mut R, output: &mut W, key: &Key) -> Result<()> {
    let mut buf_in = Box::new([0u8; NACRYPT_CHUNK_SIZE + xchacha20poly1305::ABYTES]);
    let mut pull_header = [0u8; xchacha20poly1305::HEADERBYTES];
    input
        .read_exact(&mut pull_header)
        .context("Failed to read secretstream header")?;

    let mut pull_state = PullState::init_pull(&pull_header, key)?;

    loop {
        let rlen = input.read(&mut buf_in[..])?;
        if rlen == 0 {
            break;
        }
        let final_chunk = rlen < NACRYPT_CHUNK_SIZE;

        let (decrypted_chunk, tag) = pull_state.pull(&buf_in[..rlen], None)?;
        output.write_all(&decrypted_chunk)?;

        if final_chunk && tag != TAG_FINAL {
            bail!("End of file reached before end of secretstream");
        }

        if tag == TAG_FINAL {
            let mut single_byte = [0u8; 1];
            if input.read(&mut single_byte)? != 0 {
                bail!("TAG_FINAL reached before end of file");
            }
        }
    }

    Ok(())
}
