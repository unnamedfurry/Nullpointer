#!/bin/bash

set -e
INSTALL_DIR="${1:-/opt/cross}"
MUSL_CC="https://musl.cc"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

TOOLCHAINS=(
	"i586-linux-musl"
	"mips-linux-musl"
	"mipsel-linux-musl"
	"arm-linux-musleabi"
	"arm-linux-musleabihf"
	"powerpc-linux-musl"
	"sparc-linux-musl"
	"m68k-linux-musl"
	"sh4-linux-musl"
)

for tc in "${TOOLCHAINS[@]}"; do
	tgz="${tc}-cross.tgz"
	if [ -d "${tc}-cross" ]; then
		echo "[skip] $tc already present"
		continue
	fi
	echo "[get] $tgz"
	if ! curl -sfL -o "$tgz" "${MUSL_CC}/${tgz}"; then
		echo "[warn] failed to fetch $tgz"
		continue
	fi
	tar xzf "$tgz"
	rm -f "$tgz"
	echo "[ok] $tc"
done

echo ""
echo "Add to PATH: export PATH=\"\$PATH:${INSTALL_DIR}/i586-linux-musl-cross/bin:${INSTALL_DIR}/mips-linux-musl-cross/bin:...\""
echo "Or create symlinks to /etc/xcompile/<arch>/bin for mirai-style paths"
