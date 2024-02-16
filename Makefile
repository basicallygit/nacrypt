CC = clang
CFLAGS = -Wall -Wpedantic -O2
LDFLAGS = -lsodium
TARGET = nacrypt

SRC = main.c include/crypto.c include/utils.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(TARGET)
