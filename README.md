# Nacrypt

A simple and easy-to-use file encryption utility.

# Usage
```sh
Usage: nacrypt <inputfile> -o <outputfile> [-e,-d,-v,-vv]

Options:
  -h | --help: Display this help message
  -o | --output <filename>: Output to <filename>
  -e | --encrypt: [optional] specify encrypt mode
  -d | --decrypt: [optional] specify decrypt mode
  -v | --version: [optional] print the nacrypt version info
  -vv | --verbose: [optional] print verbose output
```

# Installation
Nacrypt is available on the [AUR](https://aur.archlinux.org/packages/nacrypt)<br>
To install it simply use your favourite AUR helper or manually with makepkg -si
```sh
paru/yay -S nacrypt
```

# Building
### Dependencies
Install [libsodium](https://doc.libsodium.org/installation)<br>
libseccomp (sandboxing)<br>
libcap (tightened sandbox)<br>
Debian / Ubuntu: `sudo apt install -y libsodium-dev libseccomp-dev libcap-dev`<br>
Arch & Derivatives: `sudo pacman -S --needed libsodium libseccomp libcap`

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
It uses the xchacha20-poly1305 stream cipher with Argon2ID for key derivation.<br>
Default KDF parameters are set to SENSITIVE (1GB ram, 4 passes) and salted with 32 bytes of random data (see include/crypto.c, include/crypto.h for more)<br>
Supplied passwords, encryption keys and plaintext buffers are allocated using `sodium_malloc()`, which prevents them from appearing in dumps or being swapped to disk

### Hardening
Although great care has been taken with all allocations and buffer writes by using constant defined sizes and checks, multiple hardening options are applied<br>
Nacrypt applies a wide range of compiler hardening flags (see Makefile). `sodium_malloc()` also provides guard pages for all heap allocations<br>
On linux, the sandbox will use chroot jails, landlock and seccomp. On openbsd `pledge("stdio")` is used and on freebsd `capsicum` is used<br>

The strong cryptographic defaults and hardening make nacrypt well-suited for storage of files on untrusted cloud services which could potentially attempt to tamper with your files
