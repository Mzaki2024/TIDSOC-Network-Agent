#!/bin/bash
# 02a-install-configure-pulledpork.sh - Install and Configure PulledPork3 for TIDSOC ICS

set -euo pipefail

echo "=================================================="
echo "PHASE 2A: Installing and Configuring PulledPork3"
echo "=================================================="

# Install dependencies
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y git python3 python3-pip

# Create source directory
SRC_DIR="$HOME/snort_src"
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

# Clone and install PulledPork3
echo "Installing PulledPork3..."
if [ ! -d "pulledpork3" ]; then
    git clone https://github.com/shirkdog/pulledpork3.git
fi

# Install PulledPork3
sudo mkdir -p /usr/local/bin/pulledpork3 /usr/local/etc/pulledpork3
sudo cp pulledpork3/pulledpork.py /usr/local/bin/pulledpork3/
sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
sudo cp -r pulledpork3/lib /usr/local/bin/pulledpork3/
sudo cp pulledpork3/etc/pulledpork.conf /usr/local/etc/pulledpork3/

# Test installation
echo "Testing PulledPork3 installation..."
if /usr/local/bin/pulledpork3/pulledpork.py -V; then
    echo "PulledPork3 installed successfully!"
else
    echo "PulledPork3 installation failed!"
    exit 1
fi

# Configure PulledPork3 for TIDSOC ICS
echo "Configuring PulledPork3 for TIDSOC ICS monitoring..."

# Your existing oinkcode
OINKCODE="5c0634a44e8b91a23e66c280f2cf69a8bef39513"

# Create necessary directories
sudo mkdir -p /usr/local/etc/rules
sudo mkdir -p /usr/local/etc/so_rules

# PulledPork configuration for ICS
echo "Creating PulledPork configuration..."
sudo tee /usr/local/etc/pulledpork3/pulledpork.conf > /dev/null <<EOF
# TIDSOC PulledPork3 Configuration for ICS Monitoring

# Rule URLs
rule_url=https://www.snort.org/rules/snortrules-snapshot-31200.tar.gz|snortrules-snapshot-31200.tar.gz|$OINKCODE
rule_url=https://www.snort.org/downloads/community/snort3-community-rules.tar.gz|snort3-community-rules.tar.gz|Community

# Snort configuration
snort_path=/usr/local/bin/snort
config_path=/etc/snort/snort-tidsoc-ics.lua

# Rule processing mode
rule_mode=simple

# Rule paths
rule_path=/usr/local/etc/rules/pulledpork.rules
sid_msg=/usr/local/etc/rules/sid-msg.map

# SO rules path
sorule_path=/usr/local/etc/so_rules

# Rule management settings
registered_ruleset=true
community_ruleset=true
lightspd_ruleset=false

# Files to ignore
ignored_files=includes.rules,snort3-deleted.rules

# ICS-specific rule categories to enable
enable_rule_categories=policy,trojan-activity,attempted-admin,attempted-dos,attempted-recon,protocol-command-decode

# Include disabled rules for analysis
include_disabled_rules=false

# Logging
verbose=true
EOF

# Set proper permissions
sudo chown -R root:root /usr/local/etc/pulledpork3 /usr/local/etc/rules
sudo chmod -R 755 /usr/local/etc/pulledpork3 /usr/local/etc/rules

echo "=================================================="
echo "PHASE 2A COMPLETED SUCCESSFULLY!"
echo "=================================================="
echo "PulledPork3 installed and configured for TIDSOC ICS"
echo "Installation location: /usr/local/bin/pulledpork3/"
echo "Configuration: /usr/local/etc/pulledpork3/pulledpork.conf"
echo ""
echo "Ready for Phase 2b: ICS Rules Creation"
echo "=================================================="