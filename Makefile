CC = clang
CFLAGS = -std=gnu17 -O2 -fPIC -Wall -Wpedantic -Wextra -Wno-missing-field-initializers -Wno-unused-command-line-argument -Iinclude/ -I. -I/usr/local/include -L/usr/local/lib
LDFLAGS = -lsodium
HARDENING_CFLAGS = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-all \
	-fstack-clash-protection -fno-delete-null-pointer-checks \
	-Wconversion -Werror=conversion -Wsign-conversion -Werror=sign-conversion \
	-Wimplicit-fallthrough -Werror=implicit-fallthrough -Wformat -Wformat=2 -Werror=format
HARDENING_LDFLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fPIE -pie
CFIFLAGS = -fsanitize=cfi -flto -fvisibility=hidden
TARGET = nacrypt
SRC = main.c $(wildcard include/*.c)
OBJ = $(SRC:.c=.o)

UNAME_S = $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	ifndef NO_SANDBOX
		LDFLAGS += -lseccomp -lcap
	endif
	# Check for linux/landlock.h
	HAS_LANDLOCK := $(shell $(CC) -Wno-error -x c -include linux/landlock.h -E /dev/null >/dev/null 2>&1 && echo yes)
	ifeq ($(HAS_LANDLOCK),yes)
		CFLAGS += -DHAS_LANDLOCK_H
	endif
endif
ifeq ($(UNAME_S),OpenBSD)
	CFLAGS += -Wno-unused-parameter
endif
ifeq ($(CLANG_CFI),y)
	CFLAGS += $(CFIFLAGS)
	LDFLAGS += $(CFIFLAGS)
endif
ifeq ($(NO_SANDBOX),y)
	CFLAGS += -DNO_SANDBOX
endif
ifeq ($(ALLOW_SANDBOX_FAIL),y)
	CFLAGS += -DALLOW_SANDBOX_FAIL
endif

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -s $(CFLAGS) $(HARDENING_CFLAGS) $(LDFLAGS) $(HARDENING_LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(HARDENING_CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJ)

.PHONY: test
test: $(TARGET)
	chmod +x ./format.sh
	./format.sh --check

.PHONY: install
install: $(TARGET)
	mv $(TARGET) /usr/local/bin/$(TARGET)
