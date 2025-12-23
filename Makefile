CC = clang
CFLAGS = -O2 -Wall -Wpedantic -Wextra -Werror -Wno-missing-field-initializers -Iinclude/ -I.
LDFLAGS = -lsodium -lseccomp
HARDENINGCFLAGS = -D_FORTIFY_SOURCE=2 -fstack-protector-all \
	    -fstack-clash-protection -fno-delete-null-pointer-checks
HARDENINGLDFLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fPIE -pie
TARGET = nacrypt
SRC = main.c $(wildcard include/*.c)
OBJ = $(SRC:.c=.o)

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(HARDENINGCFLAGS) $(LDFLAGS) $(HARDENINGLDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(HARDENINGCFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJ)

.PHONY: test
test: $(TARGET)
	# Check formatting against .clang-format
	chmod +x ./format.sh
	./format.sh --check
