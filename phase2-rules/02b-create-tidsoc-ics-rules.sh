#!/bin/bash
# 02b-create-tidsoc-ics-rules.sh - Create ICS-specific rules (ALIGNED with PulledPork)

set -euo pipefail

echo "=================================================="
echo "PHASE 2B: Creating TIDSOC ICS Rules"
echo "=================================================="

# Verify PulledPork is installed and configured
if [ ! -f "/usr/local/bin/pulledpork3/pulledpork.py" ]; then
    echo "ERROR: PulledPork3 not found! Please run Phase 2a first."
    exit 1
fi

if [ ! -f "/usr/local/etc/pulledpork3/pulledpork.conf" ]; then
    echo "ERROR: PulledPork3 configuration not found! Please run Phase 2a first."
    exit 1
fi

# Create base ICS rules directory structure
sudo mkdir -p /usr/local/etc/ics_rules/{modbus,bacnet,dnp3,iec104,mms,enip,general}

echo "Creating Modbus protocol rules..."
sudo tee /usr/local/etc/ics_rules/modbus/modbus.rules > /dev/null <<'EOF'
# TIDSOC Modbus TCP Protocol Rules

# Detect unauthorized Modbus write operations in SCADA network
alert tcp any any -> 10.10.2.0/24 502 (msg:"TIDSOC MODBUS Write Multiple Coils to SCADA"; \
    flow:to_server,established; modbus_func:write_multiple_coils; \
    sid:2000001; rev:1; classtype:attempted-admin;)

alert tcp any any -> 10.10.3.0/24 502 (msg:"TIDSOC MODBUS Write Single Register to Field Device"; \
    flow:to_server,established; modbus_func:write_single_register; \
    sid:2000002; rev:1; classtype:attempted-admin;)

alert tcp any any -> 10.10.2.0/24 502 (msg:"TIDSOC MODBUS Write Multiple Registers to SCADA"; \
    flow:to_server,established; modbus_func:write_multiple_registers; \
    sid:2000003; rev:1; classtype:attempted-admin;)

# Monitor cross-network Modbus access
alert tcp 10.10.3.0/24 any -> 10.10.2.0/24 502 (msg:"TIDSOC Field Device accessing SCADA Modbus"; \
    flow:to_server,established; \
    sid:2000004; rev:1; classtype:policy-violation;)

alert tcp 10.10.2.0/24 any -> 10.10.1.0/24 502 (msg:"TIDSOC SCADA accessing Management via Modbus"; \
    flow:to_server,established; \
    sid:2000005; rev:1; classtype:policy-violation;)

# Detect external Modbus access attempts
alert tcp !10.10.0.0/16 any -> 10.10.0.0/16 502 (msg:"TIDSOC External Modbus Access Attempt"; \
    flow:to_server,established; \
    sid:2000006; rev:1; classtype:attempted-admin;)

# Monitor Modbus diagnostic and maintenance functions
alert tcp any any -> 10.10.0.0/16 502 (msg:"TIDSOC MODBUS Diagnostic Command"; \
    flow:to_server,established; modbus_func:diagnostics; \
    sid:2000007; rev:1; classtype:attempted-recon;)

alert tcp any any -> 10.10.0.0/16 502 (msg:"TIDSOC MODBUS Get Communications Event Counter"; \
    flow:to_server,established; modbus_func:get_comm_event_counter; \
    sid:2000008; rev:1; classtype:attempted-recon;)

# Monitor critical Modbus unit IDs
alert tcp any any -> 10.10.2.0/24 502 (msg:"TIDSOC MODBUS Access to Critical SCADA Unit ID 1"; \
    flow:to_server,established; modbus_unit:1; \
    sid:2000009; rev:1; classtype:attempted-admin;)

alert tcp any any -> 10.10.3.0/24 502 (msg:"TIDSOC MODBUS Access to Broadcast Unit ID 255"; \
    flow:to_server,established; modbus_unit:255; \
    sid:2000010; rev:1; classtype:attempted-admin;)

# Detect malformed Modbus packets
alert tcp any any -> 10.10.0.0/16 502 (msg:"TIDSOC MODBUS Invalid Function Code"; \
    flow:to_server,established; content:"|00 00 00 00 00 06|"; offset:0; depth:6; \
    content:"|FF|"; offset:7; depth:1; \
    sid:2000011; rev:1; classtype:protocol-command-decode;)

# Monitor excessive Modbus requests (potential DoS)
alert tcp any any -> 10.10.0.0/16 502 (msg:"TIDSOC MODBUS Excessive Requests"; \
    flow:to_server,established; \
    threshold:type both, track by_src, count 100, seconds 60; \
    sid:2000012; rev:1; classtype:attempted-dos;)

# Detect Modbus exception responses
alert tcp 10.10.0.0/16 502 -> any any (msg:"TIDSOC MODBUS Exception Response"; \
    flow:from_server,established; content:"|81|"; offset:7; depth:1; \
    sid:2000013; rev:1; classtype:protocol-command-decode;)
EOF

echo "Creating BACnet protocol rules..."
sudo tee /usr/local/etc/ics_rules/bacnet/bacnet.rules > /dev/null <<'EOF'
# TIDSOC BACnet Protocol Rules for Building Automation

# Detect BACnet write operations in SCADA and field networks
alert udp any any -> 10.10.2.0/24 47808 (msg:"TIDSOC BACNET Write Property to SCADA Network"; \
    content:"|81|"; offset:0; depth:1; content:"|0F|"; offset:1; depth:1; \
    sid:2000020; rev:1; classtype:attempted-admin;)

alert udp any any -> 10.10.3.0/24 47808 (msg:"TIDSOC BACNET Write Property to Field Devices"; \
    content:"|81|"; offset:0; depth:1; content:"|0F|"; offset:1; depth:1; \
    sid:2000021; rev:1; classtype:attempted-admin;)

# Monitor BACnet device control from external networks
alert udp !10.10.0.0/16 any -> 10.10.0.0/16 47808 (msg:"TIDSOC External BACnet Control Attempt"; \
    content:"|81|"; offset:0; depth:1; content:"|13|"; offset:1; depth:1; \
    sid:2000022; rev:1; classtype:attempted-admin;)

# Detect BACnet device reinitialize commands
alert udp any any -> 10.10.0.0/16 47808 (msg:"TIDSOC BACNET Device Reinitialize Command"; \
    content:"|81|"; offset:0; depth:1; content:"|14|"; offset:1; depth:1; \
    sid:2000023; rev:1; classtype:attempted-dos;)

# Monitor BACnet time synchronization attempts
alert udp any any -> 10.10.0.0/16 47808 (msg:"TIDSOC BACNET Time Synchronization"; \
    content:"|81|"; offset:0; depth:1; content:"|06|"; offset:1; depth:1; \
    sid:2000024; rev:1; classtype:attempted-recon;)

# Detect BACnet Who-Is broadcasts from external networks
alert udp !10.10.0.0/16 any -> 10.10.0.0/16 47808 (msg:"TIDSOC External BACNET Who-Is Request"; \
    content:"|81 0A 00 0C 01 20 FF FF 00 FF 10 08|"; \
    sid:2000025; rev:1; classtype:attempted-recon;)

# Monitor BACnet atomic write file operations
alert udp any any -> 10.10.0.0/16 47808 (msg:"TIDSOC BACNET Atomic Write File"; \
    content:"|81|"; offset:0; depth:1; content:"|1B|"; offset:1; depth:1; \
    sid:2000026; rev:1; classtype:attempted-admin;)

# Detect BACnet device communication control
alert udp any any -> 10.10.0.0/16 47808 (msg:"TIDSOC BACNET Device Communication Control"; \
    content:"|81|"; offset:0; depth:1; content:"|13|"; offset:1; depth:1; \
    sid:2000027; rev:1; classtype:attempted-admin;)
EOF

echo "Creating DNP3 protocol rules..."
sudo tee /usr/local/etc/ics_rules/dnp3/dnp3.rules > /dev/null <<'EOF'
# TIDSOC DNP3 Protocol Rules for SCADA Communications

# Detect DNP3 control operations in SCADA network
alert tcp any any -> 10.10.2.0/24 20000 (msg:"TIDSOC DNP3 Control Operation to SCADA"; \
    flow:to_server,established; dnp3_func:operate; \
    sid:2000030; rev:1; classtype:attempted-admin;)

# Monitor DNP3 write operations to field devices
alert tcp any any -> 10.10.3.0/24 20000 (msg:"TIDSOC DNP3 Write Operation to Field Device"; \
    flow:to_server,established; dnp3_func:write; \
    sid:2000031; rev:1; classtype:attempted-admin;)

# Detect external DNP3 access attempts
alert tcp !10.10.0.0/16 any -> 10.10.0.0/16 20000 (msg:"TIDSOC External DNP3 Access Attempt"; \
    flow:to_server,established; \
    sid:2000032; rev:1; classtype:attempted-admin;)

# Monitor DNP3 file transfer operations
alert tcp any any -> 10.10.0.0/16 20000 (msg:"TIDSOC DNP3 File Read Operation"; \
    flow:to_server,established; dnp3_func:file_read; \
    sid:2000033; rev:1; classtype:attempted-admin;)

alert tcp any any -> 10.10.0.0/16 20000 (msg:"TIDSOC DNP3 File Write Operation"; \
    flow:to_server,established; dnp3_func:file_write; \
    sid:2000034; rev:1; classtype:attempted-admin;)

# Detect DNP3 restart commands
alert tcp any any -> 10.10.0.0/16 20000 (msg:"TIDSOC DNP3 Cold Restart Command"; \
    flow:to_server,established; dnp3_func:cold_restart; \
    sid:2000035; rev:1; classtype:attempted-dos;)

alert tcp any any -> 10.10.0.0/16 20000 (msg:"TIDSOC DNP3 Warm Restart Command"; \
    flow:to_server,established; dnp3_func:warm_restart; \
    sid:2000036; rev:1; classtype:attempted-dos;)

# Monitor DNP3 authentication challenges
alert tcp any any -> 10.10.0.0/16 20000 (msg:"TIDSOC DNP3 Authentication Request"; \
    flow:to_server,established; dnp3_func:auth_request; \
    sid:2000037; rev:1; classtype:attempted-admin;)

# Detect DNP3 time synchronization
alert tcp any any -> 10.10.0.0/16 20000 (msg:"TIDSOC DNP3 Time Synchronization"; \
    flow:to_server,established; dnp3_func:record_current_time; \
    sid:2000038; rev:1; classtype:attempted-admin;)
EOF

echo "Creating IEC 60870-5-104 protocol rules..."
sudo tee /usr/local/etc/ics_rules/iec104/iec104.rules > /dev/null <<'EOF'
# TIDSOC IEC 60870-5-104 Protocol Rules

# Detect IEC 104 control commands to SCADA systems
alert tcp any any -> 10.10.2.0/24 2404 (msg:"TIDSOC IEC104 Control Command to SCADA"; \
    flow:to_server,established; content:"|68|"; offset:0; depth:1; \
    content:"|2D|"; offset:2; depth:1; \
    sid:2000040; rev:1; classtype:attempted-admin;)

# Monitor IEC 104 control commands to field devices
alert tcp any any -> 10.10.3.0/24 2404 (msg:"TIDSOC IEC104 Control Command to Field Device"; \
    flow:to_server,established; content:"|68|"; offset:0; depth:1; \
    content:"|2D|"; offset:2; depth:1; \
    sid:2000041; rev:1; classtype:attempted-admin;)

# Detect IEC 104 general interrogation commands
alert tcp any any -> 10.10.0.0/16 2404 (msg:"TIDSOC IEC104 General Interrogation"; \
    flow:to_server,established; content:"|68|"; offset:0; depth:1; \
    content:"|64|"; offset:2; depth:1; \
    sid:2000042; rev:1; classtype:attempted-recon;)

# Monitor IEC 104 time synchronization
alert tcp any any -> 10.10.0.0/16 2404 (msg:"TIDSOC IEC104 Time Synchronization"; \
    flow:to_server,established; content:"|68|"; offset:0; depth:1; \
    content:"|67|"; offset:2; depth:1; \
    sid:2000043; rev:1; classtype:attempted-admin;)

# Detect external IEC 104 access
alert tcp !10.10.0.0/16 any -> 10.10.0.0/16 2404 (msg:"TIDSOC External IEC104 Access Attempt"; \
    flow:to_server,established; content:"|68|"; offset:0; depth:1; \
    sid:2000044; rev:1; classtype:attempted-admin;)

# Monitor IEC 104 parameter activation
alert tcp any any -> 10.10.0.0/16 2404 (msg:"TIDSOC IEC104 Parameter Activation"; \
    flow:to_server,established; content:"|68|"; offset:0; depth:1; \
    content:"|71|"; offset:2; depth:1; \
    sid:2000045; rev:1; classtype:attempted-admin;)
EOF

echo "Creating MMS/IEC 61850 protocol rules..."
sudo tee /usr/local/etc/ics_rules/mms/mms.rules > /dev/null <<'EOF'
# TIDSOC MMS/IEC 61850 Protocol Rules

# Detect MMS write operations to SCADA systems
alert tcp any any -> 10.10.2.0/24 102 (msg:"TIDSOC MMS Write Operation to SCADA"; \
    flow:to_server,established; content:"|A0|"; offset:0; depth:1; \
    sid:2000050; rev:1; classtype:attempted-admin;)

# Monitor MMS control operations to field devices
alert tcp any any -> 10.10.3.0/24 102 (msg:"TIDSOC MMS Control Operation to Field Device"; \
    flow:to_server,established; content:"|A2|"; offset:0; depth:1; \
    sid:2000051; rev:1; classtype:attempted-admin;)

# Detect external MMS access attempts
alert tcp !10.10.0.0/16 any -> 10.10.0.0/16 102 (msg:"TIDSOC External MMS Access Attempt"; \
    flow:to_server,established; \
    sid:2000052; rev:1; classtype:attempted-admin;)

# Monitor MMS file operations
alert tcp any any -> 10.10.0.0/16 102 (msg:"TIDSOC MMS File Open Operation"; \
    flow:to_server,established; content:"|A4|"; offset:0; depth:1; \
    sid:2000053; rev:1; classtype:attempted-admin;)

# Detect MMS identify operations
alert tcp any any -> 10.10.0.0/16 102 (msg:"TIDSOC MMS Identify Request"; \
    flow:to_server,established; content:"|A1|"; offset:0; depth:1; \
    sid:2000054; rev:1; classtype:attempted-recon;)
EOF

echo "Creating EtherNet/IP protocol rules..."
sudo tee /usr/local/etc/ics_rules/enip/enip.rules > /dev/null <<'EOF'
# TIDSOC EtherNet/IP Protocol Rules

# Detect EtherNet/IP explicit messaging to SCADA
alert tcp any any -> 10.10.2.0/24 44818 (msg:"TIDSOC ENIP Explicit Message to SCADA"; \
    flow:to_server,established; content:"|6F|"; offset:0; depth:1; \
    sid:2000060; rev:1; classtype:attempted-admin;)

# Monitor EtherNet/IP explicit messaging to field devices
alert tcp any any -> 10.10.3.0/24 44818 (msg:"TIDSOC ENIP Explicit Message to Field Device"; \
    flow:to_server,established; content:"|6F|"; offset:0; depth:1; \
    sid:2000061; rev:1; classtype:attempted-admin;)

# Detect external EtherNet/IP access
alert tcp !10.10.0.0/16 any -> 10.10.0.0/16 44818 (msg:"TIDSOC External ENIP Access Attempt"; \
    flow:to_server,established; \
    sid:2000062; rev:1; classtype:attempted-admin;)

# Monitor EtherNet/IP I/O messaging on UDP
alert udp any any -> 10.10.0.0/16 2222 (msg:"TIDSOC ENIP I/O Messaging"; \
    content:"|6F|"; offset:0; depth:1; \
    sid:2000063; rev:1; classtype:policy-violation;)

# Detect EtherNet/IP list services command
alert tcp any any -> 10.10.0.0/16 44818 (msg:"TIDSOC ENIP List Services Command"; \
    flow:to_server,established; content:"|6F 00 04 00|"; offset:0; depth:4; \
    sid:2000064; rev:1; classtype:attempted-recon;)
EOF

echo "Creating general ICS security rules..."
sudo tee /usr/local/etc/ics_rules/general/tidsoc_ics.rules > /dev/null <<'EOF'
# TIDSOC General ICS Security Rules

# Network segmentation violations
alert tcp 10.10.3.0/24 any -> 10.10.1.0/24 any (msg:"TIDSOC Field Device to Management Network"; \
    flags:S; sid:2000070; rev:1; classtype:policy-violation;)

alert tcp 10.10.2.0/24 any -> 10.10.1.0/24 any (msg:"TIDSOC SCADA to Management Network"; \
    flags:S; sid:2000071; rev:1; classtype:policy-violation;)

alert tcp 10.10.3.0/24 any -> 10.10.2.0/24 any (msg:"TIDSOC Field Device to SCADA Direct Access"; \
    flags:S; sid:2000072; rev:1; classtype:policy-violation;)

# Detect potential lateral movement
alert tcp 10.10.1.0/24 any -> 10.10.3.0/24 22 (msg:"TIDSOC SSH from Management to Field Devices"; \
    flags:S; sid:2000073; rev:1; classtype:attempted-admin;)

alert tcp 10.10.1.0/24 any -> 10.10.2.0/24 22 (msg:"TIDSOC SSH from Management to SCADA"; \
    flags:S; sid:2000074; rev:1; classtype:attempted-admin;)

# Monitor unusual protocols on ICS networks
alert tcp any any -> 10.10.2.0/24 80 (msg:"TIDSOC HTTP Traffic to SCADA Network"; \
    flags:S; sid:2000075; rev:1; classtype:policy-violation;)

alert tcp any any -> 10.10.3.0/24 443 (msg:"TIDSOC HTTPS Traffic to Field Devices"; \
    flags:S; sid:2000076; rev:1; classtype:policy-violation;)

alert tcp any any -> 10.10.2.0/24 23 (msg:"TIDSOC Telnet to SCADA Network"; \
    flags:S; sid:2000077; rev:1; classtype:attempted-admin;)

alert tcp any any -> 10.10.3.0/24 23 (msg:"TIDSOC Telnet to Field Devices"; \
    flags:S; sid:2000078; rev:1; classtype:attempted-admin;)

# Detect suspicious file transfers
alert tcp any any -> 10.10.2.0/24 21 (msg:"TIDSOC FTP to SCADA Network"; \
    flags:S; sid:2000079; rev:1; classtype:policy-violation;)

alert tcp any any -> 10.10.3.0/24 21 (msg:"TIDSOC FTP to Field Devices"; \
    flags:S; sid:2000080; rev:1; classtype:policy-violation;)

# Monitor database connections to ICS networks
alert tcp any any -> 10.10.2.0/24 1433 (msg:"TIDSOC SQL Server Connection to SCADA"; \
    flags:S; sid:2000081; rev:1; classtype:policy-violation;)

alert tcp any any -> 10.10.2.0/24 3306 (msg:"TIDSOC MySQL Connection to SCADA"; \
    flags:S; sid:2000082; rev:1; classtype:policy-violation;)

# Detect potential reconnaissance activities
alert icmp any any -> 10.10.2.0/24 any (msg:"TIDSOC ICMP to SCADA Network"; \
    itype:8; threshold:type both, track by_src, count 10, seconds 60; \
    sid:2000083; rev:1; classtype:attempted-recon;)

alert icmp any any -> 10.10.3.0/24 any (msg:"TIDSOC ICMP to Field Devices"; \
    itype:8; threshold:type both, track by_src, count 10, seconds 60; \
    sid:2000084; rev:1; classtype:attempted-recon;)

# Monitor ARP activities in ICS networks
alert arp any any -> 10.10.2.0/24 any (msg:"TIDSOC ARP Activity in SCADA Network"; \
    threshold:type both, track by_src, count 20, seconds 60; \
    sid:2000085; rev:1; classtype:attempted-recon;)

alert arp any any -> 10.10.3.0/24 any (msg:"TIDSOC ARP Activity in Field Network"; \
    threshold:type both, track by_src, count 20, seconds 60; \
    sid:2000086; rev:1; classtype:attempted-recon;)
EOF

# Combine all rules into master ruleset
echo "Combining all ICS rules into master ruleset..."
sudo cat /usr/local/etc/ics_rules/modbus/modbus.rules \
    /usr/local/etc/ics_rules/bacnet/bacnet.rules \
    /usr/local/etc/ics_rules/dnp3/dnp3.rules \
    /usr/local/etc/ics_rules/iec104/iec104.rules \
    /usr/local/etc/ics_rules/mms/mms.rules \
    /usr/local/etc/ics_rules/enip/enip.rules \
    /usr/local/etc/ics_rules/general/tidsoc_ics.rules \
    > /tmp/tidsoc_ics_master.rules

sudo mv /tmp/tidsoc_ics_master.rules /usr/local/etc/rules/tidsoc_ics.rules

# Set proper ownership and permissions
sudo chown -R root:root /usr/local/etc/ics_rules /usr/local/etc/rules/tidsoc_ics.rules
sudo chmod -R 755 /usr/local/etc/ics_rules
sudo chmod 644 /usr/local/etc/rules/tidsoc_ics.rules

echo "=================================================="
echo "PHASE 2B COMPLETED SUCCESSFULLY!"
echo "=================================================="
echo "Created rule files:"
echo "  - Master ICS ruleset: /usr/local/etc/rules/tidsoc_ics.rules"
echo "  - Individual protocol rules in: /usr/local/etc/ics_rules/"
echo ""
echo "Total ICS rules created: $(grep -c '^alert' /usr/local/etc/rules/tidsoc_ics.rules)"
echo ""
echo "Files are aligned with PulledPork configuration:"
echo "  - PulledPork rules: /usr/local/etc/rules/pulledpork.rules (will be created by PulledPork)"
echo "  - ICS rules: /usr/local/etc/rules/tidsoc_ics.rules ✓"
echo "=================================================="