CC = clang
CFLAGS = -O2 -Wall -Wpedantic -Wextra -Wno-missing-field-initializers -Wno-unused-command-line-argument -Iinclude/ -I. -I/usr/local/include -L/usr/local/lib
LDFLAGS = -lsodium
UNAME_S = $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS += -lseccomp
endif
ifeq ($(UNAME_S),OpenBSD)
	CFLAGS += -Wno-unused-parameter
endif
HARDENINGCFLAGS = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-all \
	    -fstack-clash-protection -fno-delete-null-pointer-checks \
		-Wconversion -Werror=conversion -Wsign-conversion -Werror=sign-conversion \
		-Wimplicit-fallthrough -Werror=implicit-fallthrough -Wformat -Wformat=2 -Werror=format
HARDENINGLDFLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fPIE -pie
CFIFLAGS = -fsanitize=cfi -flto -fvisibility=hidden
TARGET = nacrypt
SRC = main.c $(wildcard include/*.c)
OBJ = $(SRC:.c=.o)

ifeq ($(CLANG_CFI),y)
	ifneq ($(OS),Windows_NT)
		CFLAGS += $(CFIFLAGS)
		LDFLAGS += $(CFIFLAGS)
	endif
endif

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

.PHONY: install
install: $(TARGET)
	mv $(TARGET) /usr/local/bin/$(TARGET)
