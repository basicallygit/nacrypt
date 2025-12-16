CC = cc
CFLAGS = -Wall -Wpedantic -Wextra -Werror -O2
HARDENING = -D_FORTIFY_SOURCE=2 -fstack-protector-all \
			-fstack-clash-protection -fno-delete-null-pointer-checks \
			-fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
LDFLAGS = -lsodium -lseccomp
TARGET = nacrypt

SRC = main.c include/crypto.c include/utils.c include/nacrypt_security.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(HARDENING) $^ -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(TARGET) *test.txt*

.PHONY: install
install:
	mv ./$(TARGET) /usr/local/bin/

.PHONY: test
test: $(TARGET)
	echo "This is a test message" > test.txt
	echo "t3st?pa5sw0rd" | ./$(TARGET) test.txt -o test.txt.enc -e
	echo "t3st?pa5sw0rd" | ./$(TARGET) test.txt.enc -o decoded_test.txt -d
	cmp --silent test.txt decoded_test.txt || exit 1
