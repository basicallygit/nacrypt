use libsodium_rs as sodium;

pub const NACRYPT_CHUNK_SIZE: usize = 64 * 1024;

pub const NACRYPT_KDF_ALG_DEFAULT: i32 = sodium::crypto_pwhash::ALG_ARGON2ID13;
pub const NACRYPT_OPSLIMIT_DEFAULT: u64 = 4; // OPSLIMIT_SENSITIVE
pub const NACRYPT_MEMLIMIT_DEFAULT: usize = 1073741824; // MEMLIMIT_SENSITIVE
pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

pub const SYMMETRY_ASYMMETRIC: u8 = 1;
pub const SYMMETRY_SYMMETRIC: u8 = 0;
pub const MAX_NUM_RECIPIENTS: u8 = 5;

pub const NACRYPT_PUBKEY_PREFIX: &str = "nacrypt_pubkey_";

pub const NACRYPT_DIRECTORY: &str = "~/.nacrypt";
pub const NACRYPT_SECRET_KEY_PATH: &str = "~/.nacrypt/private.key";
pub const NACRYPT_PUBLIC_KEY_PATH: &str = "~/.nacrypt/public.key";
