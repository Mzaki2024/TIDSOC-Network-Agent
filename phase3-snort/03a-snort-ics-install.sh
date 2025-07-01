#!/bin/bash
# 03a-snort-ics-install.sh - Enhanced Snort installation for TIDSOC ICS

set -euo pipefail

echo "=================================================="
echo "PHASE 3A: Enhanced Snort 3 ICS Installation"
echo "=================================================="

# Verify Phase 2 dependencies
echo "Verifying Phase 2 dependencies..."
required_files=(
    "/usr/local/bin/pulledpork3/pulledpork.py"
    "/usr/local/etc/pulledpork3/pulledpork.conf"
    "/usr/local/etc/rules/tidsoc_ics.rules"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Required file not found: $file"
        echo "Please run Phase 2a and 2b scripts first."
        exit 1
    fi
done

echo "✓ All Phase 2 dependencies verified"

# Configuration variables
SRC_DIR="$HOME/snort_src"

# System preparation with ICS tools
echo "Updating system and installing dependencies..."
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y \
  build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev \
  libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev \
  openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git \
  autoconf bison flex libcmocka-dev libnetfilter-queue-dev \
  libunwind-dev libmnl-dev ethtool python3-pip \
  google-perftools libgoogle-perftools-dev ragel libflatbuffers-dev \
  libboost-all-dev libhyperscan-dev net-tools curl jq tcpdump \
  wireshark-common tshark nmap bridge-utils \
  python3-scapy python3-pymodbus python3-bacpypes sqlite3

# Install ICS analysis tools
echo "Installing ICS analysis tools..."
sudo pip3 install pymodbus bacpypes dnp3-python scapy-industrial

# Network interface optimization for dual interface monitoring
echo "Configuring network interface optimization..."
sudo tee /etc/systemd/system/snort3-ics-nic.service > /dev/null <<'EOF'
[Unit]
Description=Optimize NICs for Snort 3 ICS monitoring
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev eth0 promisc on
ExecStart=/usr/sbin/ip link set dev eth1 promisc on
ExecStart=/usr/sbin/ethtool -K eth0 gro off lro off tso off gso off
ExecStart=/usr/sbin/ethtool -K eth1 gro off lro off tso off gso off
ExecStart=/usr/sbin/ethtool -G eth0 rx 4096 tx 4096
ExecStart=/usr/sbin/ethtool -G eth1 rx 4096 tx 4096
ExecStart=/usr/sbin/ethtool -C eth0 rx-usecs 50
ExecStart=/usr/sbin/ethtool -C eth1 rx-usecs 50
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now snort3-ics-nic.service

# Build and install Snort 3
echo "Building and installing Snort 3..."
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

# SafeC library
echo "Installing SafeC library..."
if [ ! -f "libsafec-02092020.tar.gz" ]; then
    wget -q https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-02092020.tar.gz
fi
tar -xzf libsafec-02092020.tar.gz
cd libsafec-02092020.0-g6d921f
./configure && make && sudo make install
cd ..

# libDAQ
echo "Installing libDAQ..."
if [ ! -f "libdaq-3.0.5.tar.gz" ]; then
    wget -q https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz -O libdaq-3.0.5.tar.gz
fi
tar -xzf libdaq-3.0.5.tar.gz
cd libdaq-3.0.5
./bootstrap && ./configure && make && sudo make install
cd ..

# Snort 3 Core
echo "Installing Snort 3..."
if [ ! -f "snort3-3.1.17.0.tar.gz" ]; then
    wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.17.0.tar.gz -O snort3-3.1.17.0.tar.gz
fi
tar -xzf snort3-3.1.17.0.tar.gz
cd snort3-3.1.17.0

# Configure with ICS protocol support
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc \
    --enable-static-daq --enable-large-pcap

cd build
make -j$(nproc) && sudo make install
cd ../..

sudo ldconfig

# Snort user and directory setup
echo "Setting up Snort user and directories..."
sudo groupadd snort || true
sudo useradd -r -s /sbin/nologin -c SNORT_ICS_IDS -g snort snort || true

# Create directories for Snort
sudo mkdir -p /etc/snort /var/log/snort

# Create SO rules directory if it doesn't exist
sudo mkdir -p /usr/local/etc/so_rules

# Set proper ownership and permissions
sudo chown -R snort:snort /var/log/snort
sudo chmod -R 5775 /var/log/snort

if [ -d "/usr/local/etc/so_rules" ]; then
    sudo chown -R snort:snort /usr/local/etc/so_rules
    sudo chmod -R 755 /usr/local/etc/so_rules
    echo "✓ SO rules directory permissions set"
fi

# Copy default Lua configs as reference
echo "Copying default Snort configurations as reference..."
sudo mkdir -p /etc/snort/defaults
sudo cp /usr/local/etc/snort/*.lua /etc/snort/defaults/

# Note: Custom configuration will be created in Phase 3b
echo "Default configurations saved to /etc/snort/defaults/"
echo "Custom ICS configuration will be created in Phase 3b"

# Verify installation
echo "Verifying Snort installation..."
SNORT_VERSION=$(/usr/local/bin/snort -V | head -1)
echo "✓ $SNORT_VERSION"

# Display rule statistics
echo "Rules Summary:"
echo "  ICS Rules: $(grep -c '^alert' /usr/local/etc/rules/tidsoc_ics.rules)"

echo "=================================================="
echo "PHASE 3A COMPLETED SUCCESSFULLY!"
echo "=================================================="
echo "Snort 3 installed with ICS protocol support"
echo "Network interfaces optimized for monitoring"
echo "Ready for Phase 3b: Snort Configuration"
echo "=================================================="
