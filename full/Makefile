CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=

ifeq ($(TLS),1)
ifeq ($(shell pkg-config --exists openssl && echo yes),)
$(error OpenSSL development files not found; install openssl and pkg-config)
endif
CPPFLAGS += -DTINYIRC_USE_OPENSSL $(shell pkg-config --cflags openssl)
LDLIBS += $(shell pkg-config --libs openssl)
endif

# Always rebuild: switching between `make` and `make TLS=1` must not reuse
# a binary compiled with the other mode.
.PHONY: all clean test FORCE
all: tinyirc

tinyirc: tinyirc.c FORCE
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

test: tinyirc
	TINYIRC_TEST_TLS=$(TLS) python3 -m unittest discover -s tests -v

clean:
	rm -f tinyirc
