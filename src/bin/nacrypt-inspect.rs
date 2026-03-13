use anyhow::Result;
use clap::Parser;
use nacrypt::crypto::consts::{SALT_LEN, SYMMETRY_ASYMMETRIC};
use nacrypt::header::{AsymmetricHeader, NacryptHeader, SymmetricHeader};
use std::fs::File;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "nacrypt-inspect", version, about, long_about = None)]
struct Args {
    input: PathBuf,
}

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn main() -> Result<()> {
    let args = Args::parse();

    let mut file = File::open(&args.input)?;
    let header = NacryptHeader::read_header(&mut file)?;

    println!("{}:", args.input.display());
    println!(" Nacrypt file, version: {}", header.header_version);
    println!(
        " Symmetry type: {}",
        if header.symmetry_type == SYMMETRY_ASYMMETRIC {
            "asymmetric"
        } else {
            "symmetric"
        }
    );

    if header.symmetry_type == SYMMETRY_ASYMMETRIC {
        let asymm_header = AsymmetricHeader::read_header(&mut file)?;
        println!(" Number of recipients: {}", asymm_header.num_recipients);
    } else {
        let symm_header = SymmetricHeader::read_header(&mut file)?;
        println!(" KDF: Argon2ID 1.3");
        println!(" KDF: Iterations: {}", symm_header.opslimit);
        println!(
            " KDF: Memory limit: {:.2} GiB",
            symm_header.memlimit as f64 / GIB
        );
        println!(" KDF: Salt length: {}", SALT_LEN);
    }
    Ok(())
}
