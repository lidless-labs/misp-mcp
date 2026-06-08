#!/bin/bash
# MISP MCP Proxmox LXC Installer
# Creates an LXC container on Proxmox VE with MISP MCP
# MCP server for MISP threat intelligence

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  MISP MCP - Proxmox LXC Installer${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Pre-flight
if [ ! -f /etc/pve/.version ]; then
    echo -e "${RED}Error: Must be run on a Proxmox VE host.${NC}"; exit 1
fi
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root${NC}"; exit 1
fi

# Container settings
NEXT_CTID=$(pvesh get /cluster/nextid 2>/dev/null || echo "100")
echo -e "${CYAN}Press Enter for defaults.${NC}"
echo ""

read -p "Container ID [$NEXT_CTID]: " CTID; CTID=${CTID:-$NEXT_CTID}
if pct status "$CTID" &>/dev/null; then
    echo -e "${RED}Error: CT $CTID exists.${NC}"; exit 1
fi

read -p "Hostname [misp-mcp]: " CT_HOSTNAME; CT_HOSTNAME=${CT_HOSTNAME:-misp-mcp}
read -p "Memory MB [2048]: " CT_MEMORY; CT_MEMORY=${CT_MEMORY:-2048}
read -p "Disk GB [4]: " CT_DISK; CT_DISK=${CT_DISK:-4}
read -p "CPU cores [1]: " CT_CORES; CT_CORES=${CT_CORES:-1}

# Network
echo ""; echo -e "${YELLOW}Network${NC}"
read -p "Bridge [vmbr0]: " CT_BRIDGE; CT_BRIDGE=${CT_BRIDGE:-vmbr0}
read -p "DHCP? [Y/n]: " USE_DHCP; USE_DHCP=${USE_DHCP:-Y}
NET_CONFIG="name=eth0,bridge=$CT_BRIDGE"
if [[ "${USE_DHCP,,}" == "n" ]]; then
    read -p "IP (CIDR): " CT_IP; read -p "Gateway: " CT_GW
    NET_CONFIG="$NET_CONFIG,ip=$CT_IP,gw=$CT_GW"
else
    NET_CONFIG="$NET_CONFIG,ip=dhcp"
fi

read -p "Storage [local-lvm]: " CT_STORAGE; CT_STORAGE=${CT_STORAGE:-local-lvm}

# Service config
echo ""; echo -e "${YELLOW}MISP MCP Configuration${NC}"
read -p "MISP_URL: " MISP_URL_VAL
read -p "MISP_API_KEY: " MISP_API_KEY_VAL
read -p "Port [3101]: " MCP_PORT; MCP_PORT=${MCP_PORT:-3101}

# Template
echo -e "${YELLOW}Finding Ubuntu template...${NC}"
DOWNLOADED=$(pveam list local 2>/dev/null | grep -i ubuntu | grep -i "24.04\|22.04" | awk '{print $1}' | head -1)
if [ -n "$DOWNLOADED" ]; then
    TEMPLATE="$DOWNLOADED"
else
    TNAME=$(pveam available | grep -i "ubuntu-24.04-standard" | awk '{print $2}' | head -1)
    [ -z "$TNAME" ] && TNAME=$(pveam available | grep -i "ubuntu-22.04-standard" | awk '{print $2}' | head -1)
    [ -z "$TNAME" ] && { echo -e "${RED}No Ubuntu template found.${NC}"; exit 1; }
    pveam download local "$TNAME"
    TEMPLATE="local:vztmpl/$TNAME"
fi

# Create container
echo -e "${YELLOW}Creating container $CTID...${NC}"
CT_PASSWORD=$(openssl rand -base64 12)
pct create "$CTID" "$TEMPLATE" \
    --hostname "$CT_HOSTNAME" --memory "$CT_MEMORY" --cores "$CT_CORES" \
    --rootfs "$CT_STORAGE:$CT_DISK" --net0 "$NET_CONFIG" \
    --unprivileged 1 --features nesting=1 --password "$CT_PASSWORD" --start 0

# Start and wait for network
pct start "$CTID"; sleep 10
for i in {1..30}; do
    pct exec "$CTID" -- ping -c1 8.8.8.8 &>/dev/null && break; sleep 2
done

# Install deps
echo -e "${YELLOW}Installing dependencies...${NC}"
pct exec "$CTID" -- bash -c "apt-get update && apt-get install -y curl git ca-certificates gnupg"
pct exec "$CTID" -- bash -c "mkdir -p /etc/apt/keyrings && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg"
pct exec "$CTID" -- bash -c "echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main' > /etc/apt/sources.list.d/nodesource.list"
pct exec "$CTID" -- bash -c "apt-get update && apt-get install -y nodejs"

# Clone, configure, build
echo -e "${YELLOW}Setting up MISP MCP...${NC}"
pct exec "$CTID" -- bash -c "git clone https://github.com/solomonneas/misp-mcp.git /opt/misp-mcp"
# Write .env via printf so the host-side values expand (a single-quoted
# heredoc would emit the literal $MISP_*_VAL strings). The .env holds the API
# key, so create it with a tight umask and lock it down to root afterwards.
pct exec "$CTID" -- bash -c "umask 077 && printf 'MISP_URL=%s\nMISP_API_KEY=%s\nPORT=%s\n' '$MISP_URL_VAL' '$MISP_API_KEY_VAL' '$MCP_PORT' > /opt/misp-mcp/.env && chown root:root /opt/misp-mcp/.env && chmod 600 /opt/misp-mcp/.env"
pct exec "$CTID" -- bash -c "cd /opt/misp-mcp && npm install && npm run build"

# Systemd service
pct exec "$CTID" -- bash -c "cat > /etc/systemd/system/misp-mcp.service << 'SVCEOF'
[Unit]
Description=MISP MCP
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/misp-mcp
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=10
EnvironmentFile=/opt/misp-mcp/.env

[Install]
WantedBy=multi-user.target
SVCEOF"
pct exec "$CTID" -- bash -c "systemctl daemon-reload && systemctl enable misp-mcp && systemctl start misp-mcp"

CT_IP=$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  MISP MCP installed successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo -e "  CT ID:     $CTID"
echo -e "  Hostname:  $CT_HOSTNAME"
echo -e "  IP:        $CT_IP"
echo -e "  Password:  $CT_PASSWORD"
echo -e "  Port:      $MCP_PORT"
echo ""
echo -e "  ${YELLOW}pct enter $CTID${NC}"
echo -e "  ${YELLOW}pct exec $CTID -- journalctl -u misp-mcp -f${NC}"
