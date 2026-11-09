CC ?= gcc
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wconversion -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -Iinclude -Isrc
CORE := src/errors.c src/process.c src/modules.c src/pe_exports.c src/injection.c src/x64_decode.c src/hook.c src/repl.c

.PHONY: all clean test
all: build/oculus.exe build/oculus_sample_target.exe build/oculus_sample_replacement.dll build/test_parser.exe build/test_integration.exe

build:
	@if not exist build mkdir build

build/oculus.exe: build $(CORE) src/main.c
	$(CC) $(CFLAGS) $(CORE) src/main.c -o $@

build/oculus_sample_target.exe: build samples/target/main.c
	$(CC) $(CFLAGS) samples/target/main.c -o $@

build/oculus_sample_replacement.dll: build samples/replacement_dll/replacement.c
	$(CC) $(CFLAGS) -shared samples/replacement_dll/replacement.c -o $@

build/test_parser.exe: build $(CORE) tests/test_parser.c
	$(CC) $(CFLAGS) $(CORE) tests/test_parser.c -o $@

build/test_integration.exe: build $(CORE) tests/test_integration.c
	$(CC) $(CFLAGS) $(CORE) tests/test_integration.c -o $@

test: all
	build\test_parser.exe
	build\test_integration.exe build\oculus_sample_target.exe build\oculus_sample_replacement.dll

clean:
	@if exist build rmdir /s /q build
