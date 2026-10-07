CC ?= cc
CXX ?= c++
PYTHON_CONFIG ?= python3-config
CPPFLAGS += -I../include $(shell $(PYTHON_CONFIG) --embed --cflags)
CFLAGS += -std=c11 -D_POSIX_C_SOURCE=200809L -fPIC -Wall -Wextra -Werror
LDLIBS += $(shell $(PYTHON_CONFIG) --embed --ldflags) -pthread
ifeq ($(shell uname -s),Darwin)
SHARED_FLAGS = -dynamiclib -Wl,-install_name,@rpath/libshadow6.so.1
else
SHARED_FLAGS = -shared -Wl,-soname,libshadow6.so.1
endif
all: libshadow6.so
libshadow6.so: libshadow6.so.1 Makefile
	install -m 0755 libshadow6.so.1 $@
libshadow6.so.1: shadow6.o fd_bridge.o
	$(CXX) $(SHARED_FLAGS) -o $@ $^ $(LDLIBS)
shadow6.o: shadow6.c ../include/shadow6.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
fd_bridge.o: fd_bridge.cpp ../../Core-Cpp/src/json.hpp ../../Core-Cpp/src/unicode_nfc.hpp
	$(CXX) -std=c++20 -D_GNU_SOURCE -Wall -Wextra -Werror -fPIC -c -o $@ $<
check: libshadow6.so
	$(CC) -std=c11 -Wall -Wextra -Werror -I../include -fsyntax-only ../examples/direct.c
