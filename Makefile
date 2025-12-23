CC = clang
CFLAGS = -O2 -Wall -Wpedantic -Wextra -Werror -Wno-missing-field-initializers -Iinclude/ -I.
HARDENING = -D_FORTIFY_SOURCE=2 -fstack-protector-all \
	    -fstack-clash-protection -fno-delete-null-pointer-checks \
	    -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
LDFLAGS = -lsodium -lseccomp
TARGET = nacrypt
SRC = main.c $(wildcard include/*.c)
OBJ = $(SRC:.c=.o)

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJ)

.PHONY: test
test: $(TARGET)
	# Check formatting against .clang-format
	./format.sh --check
