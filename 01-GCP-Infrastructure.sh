#!/bin/bash
# GCP TIDSOC ICS Infrastructure Setup (Production Ready)

# Configuration - Variables
PROJECT_ID="kinetic-magnet-464617-a5" # Replace with GCP project ID
VPC_NAME="TIDSOC-VPC"
REGION="us-east1"
MGMT_SUBNET="management-subnet"
MGMT_CIDR="10.10.1.0/24"
SCADA_SUBNET="scada-hmi-subnet"
SCADA_CIDR="10.10.2.0/24"
FIELD_SUBNET="field-devices-subnet"
FIELD_CIDR="10.10.3.0/24"
DMZ_SUBNET="ics-dmz-subnet"
DMZ_CIDR="10.10.4.0/24"
VM_NAME="TIDSOC-Network-Agent"
VM_ZONE="us-east1-b"
VM_TYPE="n2-standard-4"
MY_IP=$(curl -s ifconfig.me)    # public IP for SSH access
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

# SSH Key setup (CRITICAL FIX)
echo "Setting up SSH access..."
if [ ! -f ~/.ssh/id_rsa ]; then
    ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ""
    echo "✓ SSH key generated"
fi

# VM creation with idempotency and SSH key (FIXED)
echo "Checking VM: $VM_NAME"
if gcloud compute instances describe $VM_NAME --zone=$VM_ZONE --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ VM $VM_NAME already exists"
else
  echo "Creating VM: $VM_NAME"
  gcloud compute instances create $VM_NAME \
    --zone=$VM_ZONE \
    --machine-type=$VM_TYPE \
    --network-interface="subnet=$MGMT_SUBNET,private-network-ip=10.10.1.4" \
    --network-interface="subnet=$SCADA_SUBNET,private-network-ip=10.10.2.4" \
    --image-project=ubuntu-os-cloud \
    --image-family=ubuntu-2204-lts \
    --tags=$NETWORK_TAG \
    --metadata=ssh-keys="azureuser:$(cat ~/.ssh/id_rsa.pub)" \
    --metadata=startup-script='#!/bin/bash
      # Install basic tools
      apt-get update
      apt-get install -y git jq python3-pip docker.io docker-compose
      systemctl enable --now docker
      usermod -aG docker azureuser
      # Configure dual NIC routing
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
      sysctl -p
      # Persistent route configuration
      cat > /etc/netplan/90-tidsoc.yaml << EOF
      network:
        version: 2
        ethernets:
          ens4:
            dhcp4: true
          ens5:
            dhcp4: true
            routes:
              - to: 10.10.3.0/24
                via: 10.10.2.1
              - to: 10.10.4.0/24
                via: 10.10.2.1
      EOF
      netplan apply
      # Create project directories
      mkdir -p /opt/network_agent/{data,logs,config}
      chown -R azureuser:azureuser /opt/network_agent'
fi

echo "=================================================="
echo "PHASE 2: Network Configuration"
echo "=================================================="

# Route for field devices
if gcloud compute routes describe tidsoc-field-route --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ Field devices route already exists"
else
  echo "Creating route to field devices subnet"
  gcloud compute routes create tidsoc-field-route \
    --network=$VPC_NAME \
    --destination-range=10.10.3.0/24 \
    --next-hop-address=10.10.2.4 \
    --priority=100
fi

# Route for DMZ
if gcloud compute routes describe tidsoc-dmz-route --project=$PROJECT_ID >/dev/null 2>&1; then
  echo "✓ DMZ route already exists"
else
  echo "Creating route to DMZ subnet"
  gcloud compute routes create tidsoc-dmz-route \
    --network=$VPC_NAME \
    --destination-range=10.10.4.0/24 \
    --next-hop-address=10.10.2.4 \
    --priority=101
fi

# Get VM public IP
VM_IP=$(gcloud compute instances describe $VM_NAME \
  --zone=$VM_ZONE \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

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
echo "Management IP: 10.10.1.4"
echo "Monitoring IP: 10.10.2.4"
echo ""
echo "SSH to VM:"
echo "gcloud compute ssh $VM_NAME --zone=$VM_ZONE"
echo "Or: ssh azureuser@$VM_IP"
echo "=================================================="

# Save deployment info
cat > gcp-deployment-info.txt << EOF
GCP TIDSOC ICS Deployment
==========================
Project ID: $PROJECT_ID
Region: $REGION
Zone: $VM_ZONE
VPC: $VPC_NAME

Subnets:
- $MGMT_SUBNET: $MGMT_CIDR
- $SCADA_SUBNET: $SCADA_CIDR
- $FIELD_SUBNET: $FIELD_CIDR
- $DMZ_SUBNET: $DMZ_CIDR

Virtual Machine:
- Name: $VM_NAME
- Public IP: $VM_IP
- Management IP: 10.10.1.4
- Monitoring IP: 10.10.2.4

Firewall Rules:
- SSH access from: $MY_IP
- ICS Protocols: ${!ics_ports[@]}

Connect:
gcloud compute ssh $VM_NAME --zone=$VM_ZONE
SSH Command: ssh azureuser@$VM_IP
EOF

echo "Deployment information saved to gcp-deployment-info.txt"

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
echo "3. Verify dual NICs on VM:"
echo "   gcloud compute ssh $VM_NAME --zone=$VM_ZONE --command='ip addr show'"
echo ""
echo "4. Check firewall rules:"
echo "   gcloud compute firewall-rules list --filter='network:$VPC_NAME'"
echo ""
echo "=================================================="
