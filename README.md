# nacrypt
A simple and easy to use file encryption program made using libsodium

# Usage
```sh
nacrypt <input_file> -o <output_file> [-e|-d]
```
### Example
```sh
## Encrypt
nacrypt plaintext.txt -o plaintext.txt.enc

## Decrypt
nacrypt plaintext.txt.enc -o plaintext_decrypted.txt
```

# Building
Install [libsodium](https://doc.libsodium.org/installation) and libseccomp <br>
Debian / Ubuntu: `sudo apt install -y libsodium-dev libseccomp-dev`<br>
Arch & Derivatives: `sudo pacman -S libsodium libseccomp`

To build, simply run the makefile with:
```sh
make
```
or with clang CFI:
```sh
make CLANG_CFI=y
```

### Building with Nix from flake
```
nix build
```

### FreeBSD / OpenBSD
```
gmake
```

## Formatting
Format the project according to `.clang-format` using `./format.sh` or `./format.sh --check` to dry run

## Sandbox
Nacrypt applies a strict sandbox to itself before processing the input file. (see [sandbox.c](https://github.com/basicallygit/nacrypt/blob/main/include/sandbox.c))<br>
If this causes issues it can be disabled with the `-DNO_SANDBOX` CFLAG or allowed to fail with `-DALLOW_SANDBOX_FAIL`

# Installation

```sh
make && sudo make install
```
## Nix
```
nix profile install .
```
