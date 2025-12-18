# nacrypt
A simple and easy to use file encryption program made using libsodium

# Usage
```sh
nacrypt <input_file> -o <output_file> [-e|-d]
```
### Example
```sh
## Encrypt
nacrypt plaintext.txt -o plaintext.txt.encrypted -e

## Decrypt
nacrypt plaintext.txt.encryted -o plaintext_decrypted.txt -d
```

# Building
Install [libsodium](https://doc.libsodium.org/installation) and libseccomp <br>
Debian / Ubuntu: `sudo apt install -y libsodium-dev libseccomp-dev`

To build, simply run the makefile with:
```sh
make
```

### seccomp
Nacrypt applies a very strict seccomp filter to itself before processing the input file. (see [nacrypt_security.h](https://github.com/basicallygit/nacrypt/blob/main/include/nacrypt_security.c))<br>
If this causes issues it can be disabled with the `-DNO_SECCOMP` CFLAG or allowed to fail with `-DALLOW_SECCOMP_FAIL` (on platforms without seccomp)

# Installation

```sh
make && sudo make install
```
