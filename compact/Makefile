# TinyIRC 1.1.2 (plain TCP, no external libraries).
CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
PYTHON ?= python3

.PHONY: all test clean

all: tinyirc

tinyirc: tinyirc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

test: tinyirc
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -f tinyirc
