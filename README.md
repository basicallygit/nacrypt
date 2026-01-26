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

# Building
### Dependencies
Install [libsodium](https://doc.libsodium.org/installation)<br>
[Optional] libseccomp (sandboxing)<br>
[Optional] libcap (tightened sandbox)<br>
Debian / Ubuntu: `sudo apt install -y libsodium-dev libseccomp-dev libcap-dev`<br>
Arch & Derivatives: `sudo pacman -S --needed libsodium libseccomp libcap`

### To build:
```sh
make
# OR use one or multiple of the following options:
# CLANG_CFI=y (enables clang Control Flow Integrity)
# TIGHTENED_SANDBOX=y (enables extra sandboxing measures)
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
Although great care has been taken with all allocations and buffer writes by using constant defined sizes and checks, This is C after all:<br>
Nacrypt applies a wide range of compiler hardening flags (see Makefile). `sodium_malloc()` also provides guard pages for all heap allocations<br>
The default sandbox uses a strict seccomp filter only allowing basic memory management, and reading and writing to already open files. On OpenBSD/FreeBSD this uses `pledge()` and `capsicum` instead<br>
Specifying `TIGHTENED_SANDBOX=y` will additionally use namespaces, chroot and capability dropping

The strong cryptographic defaults and hardening make nacrypt well-suited for storage of files on untrusted cloud services which could potentially attempt to tamper with your files

# Installation
```sh
make && sudo make install
```
## Nix
```sh
nix profile install .
```
