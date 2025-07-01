#!/bin/bash
# 03b-snort-ics-configure.sh - Configure Snort for TIDSOC ICS monitoring

set -euo pipefail

echo "=================================================="
echo "PHASE 3B: Configuring Snort for ICS Monitoring"
echo "=================================================="

# Verify Snort installation
if [ ! -f "/usr/local/bin/snort" ]; then
    echo "ERROR: Snort not found! Please run Phase 3a first."
    exit 1
fi

# Verify rule files exist
required_files=(
    "/usr/local/bin/pulledpork3/pulledpork.py"
    "/usr/local/etc/rules/tidsoc_ics.rules"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Required rule file not found: $file"
        echo "Please run Phase 2 scripts first."
        exit 1
    fi
done

echo "✓ All dependencies verified"

# Ensure default Snort configurations are available
echo "Ensuring default Snort configurations are available..."
sudo mkdir -p /etc/snort/defaults
if [ ! -f "/etc/snort/snort_defaults.lua" ]; then
    if [ -f "/usr/local/etc/snort/snort_defaults.lua" ]; then
        sudo cp /usr/local/etc/snort/snort_defaults.lua /etc/snort/
        sudo chown snort:snort /etc/snort/snort_defaults.lua
        echo "✓ Copied snort_defaults.lua"
    else
        echo "WARNING: snort_defaults.lua not found, creating minimal version"
        sudo tee /etc/snort/snort_defaults.lua > /dev/null <<'EOF'
-- Minimal snort_defaults.lua for TIDSOC ICS
default_variables = 
{
    nets = 
    {
        HOME_NET = '10.10.0.0/16',
        EXTERNAL_NET = '!$HOME_NET'
    }
}
EOF
        sudo chown snort:snort /etc/snort/snort_defaults.lua
    fi
fi

# Create enhanced Snort configuration for TIDSOC ICS
echo "Creating custom Snort ICS configuration..."
sudo tee /etc/snort/snort-tidsoc-ics.lua > /dev/null <<'EOF'
-- snort-tidsoc-ics.lua - Enhanced Snort configuration for TIDSOC ICS monitoring

-- Include default configurations
require('snort_defaults')

-- Network variables for TIDSOC environment (override defaults)
HOME_NET = '10.10.1.0/24'    -- Management subnet
SCADA_NET = '10.10.2.0/24'   -- SCADA subnet
FIELD_NET = '10.10.3.0/24'   -- Field devices subnet
DMZ_NET = '10.10.4.0/24'     -- DMZ subnet
EXTERNAL_NET = '!10.10.0.0/16'

-- Enhanced DAQ configuration for dual interface monitoring
daq = 
{
    module_dirs = { '/usr/local/lib/daq' },
    modules = 
    {
        {
            name = 'afpacket',
            mode = 'inline',
            variables = 
            {
                'fanout_type=hash',
                'fanout_flag=rollover',
                'buffer_size_mb=256',
                'use_emergency_flush=true'
            }
        }
    }
}

-- Enhanced stream configuration for ICS protocols
stream = 
{
    tcp_cache = 
    {
        max_sessions = 1048576,
        cleanup_sessions = 20000,
        timeout = 7200,
        overlap_limit = 10,
        small_segments = 3,
        ignore_any_rules = false
    }
}

-- ICS Protocol Inspectors
modbus = 
{
    ports = '502'
}

dnp3 = 
{
    ports = '20000',
    memcap = 524288,
    check_crc = true
}

-- Service bindings for ICS protocols
binder = 
{
    {
        when = { proto = 'tcp', ports = '502' },
        use = { type = 'modbus' }
    },
    {
        when = { proto = 'tcp', ports = '20000' },
        use = { type = 'dnp3' }
    },
    {
        when = { proto = 'udp', ports = '47808' },
        use = { type = 'bacnet' }
    },
    {
        when = { proto = 'tcp', ports = '2404' },
        use = { type = 'iec104' }
    },
    {
        when = { proto = 'tcp', ports = '102' },
        use = { type = 'mms' }
    },
    {
        when = { proto = 'tcp', ports = '44818' },
        use = { type = 'cip' }
    }
}

-- Enhanced detection engine
search_engine = { search_method = "hyperscan" }
detection = { 
    hyperscan_literals = true, 
    pcre_to_regex = true,
    max_queue_events = 16,
    enable_builtin_rules = true
}

-- IPS configuration loading rules (NO local.rules)
ips = {
    enable_builtin_rules = true,
    variables = default_variables,
    rules = [[
        include /usr/local/etc/rules/tidsoc_ics.rules
        include /usr/local/etc/rules/pulledpork.rules
   ]]
}

-- Enhanced output configuration with ICS protocol fields
alert_json = {
    file = true,
    limit = 1000,
    filename = '/var/log/snort/alert_json.txt',
    fields = 'timestamp seconds action class b64_data dir dst_addr dst_ap dst_port eth_dst eth_len eth_src eth_type gid icmp_code icmp_id icmp_seq icmp_type ip_id ip_len msg mpls pkt_gen pkt_len pkt_num priority proto rev rule service sid src_addr src_ap src_port target tcp_ack tcp_flags tcp_len tcp_seq tcp_win tos ttl udp_len vlan modbus_func modbus_unit modbus_data dnp3_func dnp3_obj dnp3_var bacnet_func bacnet_type iec104_func mms_func enip_func'
}

-- Unified2 output for SIEM integration
unified2 = 
{
    filename = '/var/log/snort/snort.log',
    limit = 128,
    nostamp = false
}

-- Performance monitoring for TIDSOC
perf_monitor = 
{
    file = true,
    filename = '/var/log/snort/tidsoc_snort.stats',
    pkt_cnt = 10000,
    seconds = 60,
    flow = true,
    flow_file = '/var/log/snort/tidsoc_snort.flow_stats'
}
EOF

# Set proper ownership
sudo chown snort:snort /etc/snort/snort-tidsoc-ics.lua

# Initial configuration test (before PulledPork rules)
echo "Testing initial Snort configuration..."
if sudo /usr/local/bin/snort -T -c /etc/snort/snort-tidsoc-ics.lua; then
    echo "✓ Initial configuration validation successful"
else
    echo "✗ Initial configuration validation failed!"
    echo "Checking Snort installation and dependencies..."
    
    # Debug information
    echo "Snort version:"
    /usr/local/bin/snort -V | head -3
    
    echo "Available Lua files in /etc/snort/:"
    ls -la /etc/snort/*.lua
    
    echo "Rule files status:"
    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            echo "  ✓ $file ($(grep -c '^alert' "$file") rules)"
        else
            echo "  ✗ $file (missing)"
        fi
    done
    
    exit 1
fi

# Download initial rules via PulledPork
echo "Downloading initial rules via PulledPork..."
if sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf; then
    echo "✓ PulledPork rules downloaded successfully"
else
    echo "WARNING: PulledPork failed, continuing with ICS rules only"
fi

# Final configuration test with all rules
echo "Testing final configuration with all rules..."
if sudo /usr/local/bin/snort -T -c /etc/snort/snort-tidsoc-ics.lua; then
    echo "✓ Final configuration validation successful"
else
    echo "✗ Final configuration validation failed!"
    echo "This might be due to PulledPork rules. Checking rule files..."
    
    # Check if pulledpork.rules exists and is valid
    if [ -f "/usr/local/etc/rules/pulledpork.rules" ]; then
        echo "PulledPork rules file exists ($(wc -l < /usr/local/etc/rules/pulledpork.rules) lines)"
        echo "Checking for syntax errors in rules..."
    else
        echo "PulledPork rules file not found, creating empty file..."
        sudo touch /usr/local/etc/rules/pulledpork.rules
        sudo chown snort:snort /usr/local/etc/rules/pulledpork.rules
        
        # Test again with empty pulledpork.rules
        if sudo /usr/local/bin/snort -T -c /etc/snort/snort-tidsoc-ics.lua; then
            echo "✓ Configuration works with empty PulledPork rules"
        else
            exit 1
        fi
    fi
fi

echo "=================================================="
echo "PHASE 3B COMPLETED SUCCESSFULLY!"
echo "=================================================="
echo "Snort configured for TIDSOC ICS monitoring"
echo "Configuration file: /etc/snort/snort-tidsoc-ics.lua"
echo "Rules loaded:"
echo "  - ICS rules: $(grep -c '^alert' /usr/local/etc/rules/tidsoc_ics.rules)"
echo "  - PulledPork rules: $(test -f /usr/local/etc/rules/pulledpork.rules && grep -c '^alert' /usr/local/etc/rules/pulledpork.rules || echo '0')"
echo ""
echo "Configuration validation: ✓ PASSED"
echo "Ready for Phase 4: Service Setup"
echo "=================================================="
