# Nacrypt

A simple and easy-to-use file encryption utility.

# Usage
```sh
Usage: nacrypt <inputfile> -o <outputfile> [-e,-d,-r,-p,-vv]

Options:
  -h, --help                Display this help message
  -o, --output <filename>   Output to <filename>
  -e, --encrypt [optional]  Specify encrypt mode
  -d, --decrypt [optional]  Specify decrypt mode
  -g, --gen-key             Generate a new keypair
  -R, --regen-public        Regenerate your public key if its lost
  -r, --recipient <pubkey>  Encrypt this file to <pubkey>
  -p, --private-key <path>  Specify custom path to private key
  -v, --version             Print nacrypt version info
  -vv, --verbose            Print verbose output
```

## Symmetric example
```sh
# To ENCRYPT
$ nacrypt my_important_file.txt -o txt.enc
Please create a password: password123
Re-enter password: password123
# To DECRYPT
$ nacrypt txt.enc -o decrypted.txt
Enter password for txt.enc: password123
$ md5sum my_important_file.txt decrypted.txt
# Same hash
```

## Asymmetric example
```sh
# To ENCRYPT
$ nacrypt shared_file.txt -o txt.enc -r nacrypt_pubkey_RECIPIENT_PUBKEY
# To DECRYPT (recipient side)
$ nacrypt txt.enc -o decrypted.txt
Please enter password for private key: password123
# Recipient has same file as the sender
```

# Installation
Nacrypt is available on the [AUR](https://aur.archlinux.org/packages/nacrypt)<br>
To install it simply use your favourite AUR helper or manually with makepkg -si
```sh
$ paru/yay -S nacrypt
```

# Building
### Dependencies
Install [libsodium](https://doc.libsodium.org/installation)<br>
libseccomp (sandbox on linux)<br>
libcap (sandbox on linux)<br>
Debian / Ubuntu: `sudo apt install -y libsodium-dev libseccomp-dev libcap-dev`<br>
Arch & Derivatives: `sudo pacman -S --needed libsodium libseccomp libcap`
libseccomp and libcap are not necessary on \*BSD systems, or when `NO_SANDBOX=y` is set

### To build:
```sh
make
# OR use one or multiple of the following options:
# CLANG_CFI=y (enables clang Control Flow Integrity)
# ALLOW_SANDBOX_FAIL=y (treats sandbox failing to apply as non-fatal)
# NO_SANDBOX=y (completely disable the sandbox)
make OPTION=y
```

### Building from nix flake:
```sh
nix build
```

### FreeBSD / OpenBSD
```sh
gmake
```

# Security
Nacrypt is designed to be safe by design, using secure defaults for all cryptographic operations.<br>

### Cryptography
File encryption is done using the xchacha20-poly1305 AEAD and key derivation is done using Argon2ID.<br>
Default KDF parameters are set to SENSITIVE (1GB ram, 4 passes) and salted with 32 bytes of random data (see include/crypto.c, include/crypto.h for more)<br>
Supplied passwords, encryption keys and plaintext buffers are allocated using `sodium_malloc()`, which prevents them from appearing in dumps or being swapped to disk<br>
Private keys are encrypted on disk inside libsodium `crypto\_box`es. In asymmetric mode, the symmetric file key is wrapped inside a sealed `crypto_box_seal` to the recipients public key, which only the corresponding private key can unseal.<br>
<br>
<b>WARNING: (post-quantum)</b> Asymmetric encryption (public/private key) is done using ECDH over the 25519 montgomery curve. This is not resistant against future quantum computers. If your threat model includes an adversary harvesting your files now and breaking them later with a quantum computer (HNDL), please use either symmetric mode (password, which <b>IS</b> quantum proof), or age, which supports post-quantum key exchanges (at the downside of having extremely long public keys).<br>
<br>
<b>WARNING: (signatures)</b> In asymmetric mode, while nacrypt CAN detect if a message has been tampered with in transit, it <b>CANNOT</b> verify the sender's identity for a message. This has the benefit of the sender remaining anonymous, however if you need to verify the sender, please use another tool such as minisign on top of nacrypt to verify sender identities.

### Hardening
Although great care has been taken with all allocations and buffer writes by using constant defined sizes and checks, multiple hardening options are applied<br>
Nacrypt applies a wide range of compiler hardening flags (see Makefile). `sodium_malloc()` also provides guard pages for all heap allocations<br>
On linux, the sandbox will use chroot jails, landlock and seccomp. On openbsd `pledge("stdio")` is used and on freebsd `capsicum` is used<br>

The strong cryptographic defaults and hardening make nacrypt well-suited for storage of files on untrusted cloud services which could potentially attempt to tamper with your files
