ERL ?= erl
CC ?= musl-gcc
AR ?= ar
OBJ := obj
ERTS_INCLUDE := $(shell $(ERL) -noshell -eval 'io:put_chars(code:root_dir()),halt().' 2>/dev/null)/usr/include
SODIUM_CFLAGS ?= $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS ?= $(shell pkg-config --libs libsodium 2>/dev/null || printf '%s' -lsodium)

.PHONY: nif clean
nif: $(OBJ)/libshadow6_sodium.a

$(OBJ)/libshadow6_sodium.a: c_src/shadow6_sodium.c
	@mkdir -p $(OBJ)
	$(CC) -std=c11 -O2 -fPIE -fstack-protector-strong -D_GNU_SOURCE \
		-DSHADOW6_STATIC_NIF -D_FORTIFY_SOURCE=2 -Wall -Wextra -Werror \
		-I$(ERTS_INCLUDE) -I../.tools/gleam/musl/include -c $< -o $(OBJ)/shadow6_sodium.o
	$(AR) rcs $@ $(OBJ)/shadow6_sodium.o

clean:
	rm -rf $(OBJ) build shadow6-gleam shadow6-gleam-crosed
