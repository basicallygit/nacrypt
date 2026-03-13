use anyhow::{Result, anyhow};
use dirs;

pub fn expand_tilde(path: &str) -> Result<String> {
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("Failed to get home directory"))?;

    Ok(path.replacen("~", &home_dir.to_string_lossy(), 1))
}
