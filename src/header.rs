use crate::crypto::consts::{
    MAX_NUM_RECIPIENTS, SALT_LEN, SYMMETRY_ASYMMETRIC, SYMMETRY_SYMMETRIC,
};
use anyhow::{Result, bail};
use libsodium_rs as sodium;
use sodium::crypto_secretbox;
use std::io::{Read, Write};

pub const NACRYPT_MAGIC: [u8; 4] = [0x4E, 0x41, 0x1F, 0xF0];
pub const HEADER_VERSION: u8 = 1;

pub struct NacryptHeader {
    pub magic: [u8; 4],
    pub header_version: u8,
    pub symmetry_type: u8,
}

pub struct SymmetricHeader {
    pub opslimit: u32,
    pub memlimit: u32,
    pub salt: [u8; SALT_LEN],
}

pub struct AsymmetricHeader {
    pub num_recipients: u8,
}

pub struct SecretKeyHeader {
    pub opslimit: u32,
    pub memlimit: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: crypto_secretbox::Nonce,
}

impl NacryptHeader {
    pub fn new(symmetry_type: u8) -> Self {
        Self {
            magic: NACRYPT_MAGIC,
            header_version: HEADER_VERSION,
            symmetry_type,
        }
    }

    pub fn read_header<R: Read>(reader: &mut R) -> Result<Self> {
        let mut magic_buf = [0u8; 4];
        let mut header_version_buf = [0u8; 1];
        let mut symmetry_type_buf = [0u8; 1];

        reader.read_exact(&mut magic_buf)?;
        reader.read_exact(&mut header_version_buf)?;
        reader.read_exact(&mut symmetry_type_buf)?;

        if magic_buf != NACRYPT_MAGIC {
            bail!("Not a nacrypt file");
        }

        if header_version_buf[0] != HEADER_VERSION {
            bail!("Unknown nacrypt header version, possibly outdated program");
        }

        if symmetry_type_buf[0] != SYMMETRY_ASYMMETRIC && symmetry_type_buf[0] != SYMMETRY_SYMMETRIC
        {
            bail!("Invalid symmetry byte");
        }

        Ok(Self {
            magic: NACRYPT_MAGIC,
            header_version: header_version_buf[0],
            symmetry_type: symmetry_type_buf[0],
        })
    }

    pub fn write_header<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.magic)?;
        writer.write_all(&[self.header_version])?;
        writer.write_all(&[self.symmetry_type])?;
        Ok(())
    }
}

impl SymmetricHeader {
    pub fn new(opslimit: u32, memlimit: u32, salt: [u8; SALT_LEN]) -> Self {
        Self {
            opslimit,
            memlimit,
            salt,
        }
    }

    pub fn read_header<R: Read>(reader: &mut R) -> Result<Self> {
        let mut opslimit_buf = [0u8; 4];
        let mut memlimit_buf = [0u8; 4];
        let mut salt_buf = [0u8; SALT_LEN];
        reader.read_exact(&mut opslimit_buf)?;
        reader.read_exact(&mut memlimit_buf)?;
        reader.read_exact(&mut salt_buf)?;

        let header = Self {
            opslimit: u32::from_be_bytes(opslimit_buf),
            memlimit: u32::from_be_bytes(memlimit_buf),
            salt: salt_buf,
        };

        if header.opslimit == 0 {
            bail!("Invalid opslimit");
        }

        if header.memlimit == 0 {
            bail!("Invalid memlimit");
        }

        Ok(header)
    }

    pub fn write_header<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let net_opslimit = self.opslimit.to_be_bytes();
        let net_memlimit = self.memlimit.to_be_bytes();

        writer.write_all(&net_opslimit)?;
        writer.write_all(&net_memlimit)?;
        writer.write_all(&self.salt)?;
        Ok(())
    }
}

impl AsymmetricHeader {
    pub fn new(num_recipients: u8) -> Self {
        Self { num_recipients }
    }

    pub fn read_header<R: Read>(reader: &mut R) -> Result<Self> {
        let mut num_recipients_buf = [0u8; 1];
        reader.read_exact(&mut num_recipients_buf)?;

        if num_recipients_buf[0] > MAX_NUM_RECIPIENTS {
            bail!("Too many recipients in file");
        }

        Ok(Self {
            num_recipients: num_recipients_buf[0],
        })
    }

    pub fn write_header<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Sanity check
        if self.num_recipients > MAX_NUM_RECIPIENTS {
            bail!("Too many recipients");
        }

        writer.write_all(&[self.num_recipients])?;
        Ok(())
    }
}

impl SecretKeyHeader {
    pub fn new(
        opslimit: u32,
        memlimit: u32,
        salt: [u8; SALT_LEN],
        nonce: crypto_secretbox::Nonce,
    ) -> Self {
        Self {
            opslimit,
            memlimit,
            salt,
            nonce,
        }
    }

    pub fn read_header<R: Read>(reader: &mut R) -> Result<Self> {
        let mut opslimit_buf = [0u8; 4];
        let mut memlimit_buf = [0u8; 4];
        let mut salt_buf = [0u8; SALT_LEN];
        let mut nonce_buf = [0u8; crypto_secretbox::NONCEBYTES];
        reader.read_exact(&mut opslimit_buf)?;
        reader.read_exact(&mut memlimit_buf)?;
        reader.read_exact(&mut salt_buf)?;
        reader.read_exact(&mut nonce_buf)?;

        let header = Self {
            opslimit: u32::from_be_bytes(opslimit_buf),
            memlimit: u32::from_be_bytes(memlimit_buf),
            salt: salt_buf,
            nonce: crypto_secretbox::Nonce::from_bytes(nonce_buf),
        };

        if header.opslimit == 0 {
            bail!("Invalid opslimit");
        }

        if header.memlimit == 0 {
            bail!("Invalid memlimit");
        }

        Ok(header)
    }

    pub fn write_header<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let net_opslimit = self.opslimit.to_be_bytes();
        let net_memlimit = self.memlimit.to_be_bytes();

        writer.write_all(&net_opslimit)?;
        writer.write_all(&net_memlimit)?;
        writer.write_all(&self.salt)?;
        writer.write_all(self.nonce.as_bytes())?;
        Ok(())
    }
}
