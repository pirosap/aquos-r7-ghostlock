# AQUOS R7 build for ghostlock510 (single-file exploit).
#
# Requires the Android NDK clang targeting aarch64-linux-android29
# (tested with NDK r30).  Add the NDK toolchain bin/ directory to PATH,
# or override CC/STRIP:
#   make CC=/path/to/aarch64-linux-android29-clang STRIP=/path/to/llvm-strip

CC ?= aarch64-linux-android29-clang
STRIP ?= llvm-strip

all: build/ghostlock510 build/r7probe

build/ghostlock510: src/ghostlock510.c
	mkdir -p build
	$(CC) -O2 -Wall -Wextra -Werror -static -pthread $< -o $@

build/r7probe: tools/r7probe.c
	mkdir -p build
	$(CC) -O2 -Wall -Wextra -static $< -o $@

# Reduce the shipped static binary from ~3.4 MB to ~0.6 MB.
strip: build/ghostlock510
	$(STRIP) build/ghostlock510

clean:
	rm -f build/ghostlock510 build/r7probe

.PHONY: all strip clean
