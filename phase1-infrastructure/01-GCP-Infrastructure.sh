#!/bin/bash
# GCP TIDSOC ICS Infrastructure Setup (Single VPC - Production Ready)

# Configuration - Single VPC Architecture
PROJECT_ID="kinetic-magnet-464617-a5"
VPC_NAME="tidsoc-vpc"
REGION="us-east1"
MGMT_SUBNET="management-subnet"
MGMT_CIDR="10.10.1.0/24"
SCADA_SUBNET="scada-hmi-subnet"
SCADA_CIDR="10.10.2.0/24"
FIELD_SUBNET="field-devices-subnet"
FIELD_CIDR="10.10.3.0/24"
DMZ_SUBNET="ics-dmz-subnet"
DMZ_CIDR="10.10.4.0/24"
VM_NAME="tidsoc-network-agent"
VM_ZONE="us-east1-b"
VM_TYPE="n2-standard-4"
MY_IP=$(curl -s ifconfig.me)
NETWORK_TAG="tidsoc-network-agent"

# Set active project
gcloud config set project $PROJECT_ID

echo "=================================================="
echo "PHASE 1: Creating TIDSOC ICS GCP Infrastructure"
echo "=================================================="

# Check if VPC already exists
if gcloud compute networks describe $VPC_NAME --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ VPC $VPC_NAME already exists"
else
  echo "Creating VPC: $VPC_NAME"
  gcloud compute networks create $VPC_NAME \
    --subnet-mode=custom \
    --bgp-routing-mode=regional \
    --mtu=1460
fi

# Create subnets with idempotency
declare -A subnets=(
  [$MGMT_SUBNET]=$MGMT_CIDR
  [$SCADA_SUBNET]=$SCADA_CIDR
  [$FIELD_SUBNET]=$FIELD_CIDR
  [$DMZ_SUBNET]=$DMZ_CIDR
)

for subnet in "${!subnets[@]}"; do
  cidr=${subnets[$subnet]}
  if gcloud compute networks subnets describe $subnet --region=$REGION --project=$PROJECT_ID >/dev/null 2>&1; then
    echo "✓ Subnet $subnet ($cidr) already exists"
  else
    echo "Creating subnet: $subnet ($cidr)"
    gcloud compute networks subnets create $subnet \
      --network=$VPC_NAME \
      --range=$cidr \
      --region=$REGION
  fi
done

# Firewall rules with idempotency
echo "Creating firewall rules..."

# SSH Rule
if gcloud compute firewall-rules describe allow-ssh --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ SSH rule already exists"
else
  gcloud compute firewall-rules create allow-ssh \
    --network=$VPC_NAME \
    --allow=tcp:22 \
    --direction=INGRESS \
    --source-ranges=$MY_IP/32 \
    --priority=1000 \
    --target-tags=$NETWORK_TAG
fi

# ICS Protocol Rules (Complete set matching Azure)
declare -A ics_ports=(
  ["allow-bacnet"]="udp:47808"
  ["allow-modbus"]="tcp:502"
  ["allow-dnp3"]="tcp:20000"
  ["allow-iec104"]="tcp:2404"
  ["allow-mms"]="tcp:102"
  ["allow-enip"]="tcp:44818"
  ["allow-http"]="tcp:80"
  ["allow-https"]="tcp:443"
  ["allow-api"]="tcp:5001"
)

for rule_name in "${!ics_ports[@]}"; do
  port=${ics_ports[$rule_name]}
  if gcloud compute firewall-rules describe $rule_name --project=$PROJECT_ID >/dev/null 2>&1; then
    echo "✓ $rule_name rule already exists"
  else
    echo "Creating rule: $rule_name ($port)"
    gcloud compute firewall-rules create $rule_name \
      --network=$VPC_NAME \
      --allow=$port \
      --direction=INGRESS \
      --source-ranges=0.0.0.0/0 \
      --priority=1001 \
      --target-tags=$NETWORK_TAG
  fi
done

# Internal communication rule
if gcloud compute firewall-rules describe allow-internal --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ Internal traffic rule already exists"
else
  gcloud compute firewall-rules create allow-internal \
    --network=$VPC_NAME \
    --allow=all \
    --direction=INGRESS \
    --source-ranges=10.10.0.0/16 \
    --priority=1010 \
    --target-tags=$NETWORK_TAG
fi

# SSH Key setup
echo "Setting up SSH access..."
if [ ! -f ~/.ssh/id_rsa ]; then
    ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ""
    echo "✓ SSH key generated"
fi

# VM creation with SINGLE NIC (FIXED)
echo "Checking VM: $VM_NAME"
if gcloud compute instances describe $VM_NAME --zone=$VM_ZONE --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ VM $VM_NAME already exists"
else
  echo "Creating VM: $VM_NAME with single NIC"
  
  # Create startup script file
  cat > /tmp/startup-script.sh << 'EOF'
#!/bin/bash
# Update system
apt-get update
apt-get install -y git jq python3-pip docker.io docker-compose curl

# Enable and start Docker
systemctl enable --now docker
usermod -aG docker znm6

# Configure IP forwarding for routing
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Create project directories
mkdir -p /opt/network_agent/{data,logs,config}
chown -R znm6:znm6 /opt/network_agent

# Configure routing for all subnets through single interface
cat > /etc/netplan/90-tidsoc.yaml << NETPLAN_EOF
network:
  version: 2
  ethernets:
    ens4:
      dhcp4: true
      routes:
        - to: 10.10.2.0/24
          via: 10.10.1.1
        - to: 10.10.3.0/24
          via: 10.10.1.1
        - to: 10.10.4.0/24
          via: 10.10.1.1
NETPLAN_EOF
netplan apply

# Install BACnet tools
pip3 install BAC0 pandas requests

echo "VM setup completed" > /var/log/startup-complete.log
EOF

  gcloud compute instances create $VM_NAME \
    --zone=$VM_ZONE \
    --machine-type=$VM_TYPE \
    --network-interface="subnet=$MGMT_SUBNET,private-network-ip=10.10.1.4" \
    --image-project=ubuntu-os-cloud \
    --image-family=ubuntu-2204-lts \
    --tags=$NETWORK_TAG \
    --metadata=ssh-keys="znm6:$(cat ~/.ssh/id_rsa.pub)" \
    --metadata-from-file=startup-script=/tmp/startup-script.sh
    
  # Clean up temp file
  rm /tmp/startup-script.sh
fi

echo "=================================================="
echo "PHASE 2: Network Configuration"
echo "=================================================="

# Create routes for network segmentation (single NIC routing)
echo "Configuring network routes for single NIC architecture..."

# Route for SCADA subnet
if gcloud compute routes describe tidsoc-scada-route --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ SCADA route already exists"
else
  echo "Creating route to SCADA subnet"
  gcloud compute routes create tidsoc-scada-route \
    --network=$VPC_NAME \
    --destination-range=10.10.2.0/24 \
    --next-hop-instance=$VM_NAME \
    --next-hop-instance-zone=$VM_ZONE \
    --priority=100
fi

# Route for field devices
if gcloud compute routes describe tidsoc-field-route --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ Field devices route already exists"
else
  echo "Creating route to field devices subnet"
  gcloud compute routes create tidsoc-field-route \
    --network=$VPC_NAME \
    --destination-range=10.10.3.0/24 \
    --next-hop-instance=$VM_NAME \
    --next-hop-instance-zone=$VM_ZONE \
    --priority=101
fi

# Route for DMZ
if gcloud compute routes describe tidsoc-dmz-route --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ DMZ route already exists"
else
  echo "Creating route to DMZ subnet"
  gcloud compute routes create tidsoc-dmz-route \
    --network=$VPC_NAME \
    --destination-range=10.10.4.0/24 \
    --next-hop-instance=$VM_NAME \
    --next-hop-instance-zone=$VM_ZONE \
    --priority=102
fi

# Get VM public IP
VM_IP=$(gcloud compute instances describe $VM_NAME \
  --zone=$VM_ZONE \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || echo "Not assigned")

echo "=================================================="
echo "DEPLOYMENT COMPLETE!"
echo "=================================================="
echo "VPC: $VPC_NAME"
echo "Management Subnet: $MGMT_SUBNET ($MGMT_CIDR)"
echo "SCADA/HMI Subnet: $SCADA_SUBNET ($SCADA_CIDR)"
echo "Field Devices Subnet: $FIELD_SUBNET ($FIELD_CIDR)"
echo "DMZ Subnet: $DMZ_SUBNET ($DMZ_CIDR)"
echo "VM Name: $VM_NAME"
echo "Public IP: $VM_IP"
echo "Primary IP: 10.10.1.4 (Management)"
echo ""
echo "Network Architecture: Single NIC with routing"
echo "All subnets accessible through management interface"
echo ""
echo "SSH to VM:"
echo "gcloud compute ssh $VM_NAME --zone=$VM_ZONE"
echo "Or: ssh znm6@$VM_IP"
echo "=================================================="

# Save deployment info
cat > ~/gcp-deployment-info.txt << EOF
GCP TIDSOC ICS Deployment (Single VPC)
======================================
Project ID: $PROJECT_ID
Region: $REGION
Zone: $VM_ZONE
VPC: $VPC_NAME

Subnets:
- $MGMT_SUBNET: $MGMT_CIDR (Primary)
- $SCADA_SUBNET: $SCADA_CIDR (Routed)
- $FIELD_SUBNET: $FIELD_CIDR (Routed)
- $DMZ_SUBNET: $DMZ_CIDR (Routed)

Virtual Machine:
- Name: $VM_NAME
- Public IP: $VM_IP
- Primary IP: 10.10.1.4
- Architecture: Single NIC with routing

Network Access:
- Management: Direct (10.10.1.4)
- SCADA/HMI: Routed via 10.10.1.4
- Field Devices: Routed via 10.10.1.4
- DMZ: Routed via 10.10.1.4

Connect:
gcloud compute ssh $VM_NAME --zone=$VM_ZONE
SSH Command: ssh znm6@$VM_IP

Next Steps:
1. SSH into VM and verify routing: ip route
2. Test network connectivity to all subnets
3. Deploy BACnet agent code
4. Configure Snort for network monitoring
EOF

echo "Deployment information saved to ~/gcp-deployment-info.txt"

# Verification commands
echo ""
echo "=================================================="
echo "POST-DEPLOYMENT VERIFICATION"
echo "=================================================="
echo "Run these commands to verify your deployment:"
echo ""
echo "1. Check VM status:"
echo "   gcloud compute instances describe $VM_NAME --zone=$VM_ZONE"
echo ""
echo "2. Test SSH connectivity:"
echo "   gcloud compute ssh $VM_NAME --zone=$VM_ZONE"
echo ""
echo "3. Verify network interface and routing:"
echo "   gcloud compute ssh $VM_NAME --zone=$VM_ZONE --command='ip addr show && ip route'"
echo ""
echo "4. Check firewall rules:"
echo "   gcloud compute firewall-rules list --filter='network:$VPC_NAME'"
echo ""
echo "5. Test BACnet port accessibility:"
echo "   gcloud compute ssh $VM_NAME --zone=$VM_ZONE --command='sudo netstat -tulpn | grep 47808'"
echo ""
echo "=================================================="