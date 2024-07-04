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
Install [libsodium](https://doc.libsodium.org/installation)

To build, simply run the makefile with:
```sh
make
```

# Installation

```sh
make && sudo make install
```
