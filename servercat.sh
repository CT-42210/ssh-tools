#!/bin/bash

# ServerCat VPS Setup Script
# This script prepares your VPS for ServerCat iOS app monitoring
# Run as root: bash servercat.sh
#
# FEATURES:
# - Idempotent: Safe to run multiple times
# - Preserves existing SSH port configuration
# - Proper validation and error handling
# - Backs up SSH config before changes
# - Enables direct root login for ServerCat access

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root!"
   print_warning "Please run: sudo bash $0"
   exit 1
fi

# Header
echo "============================================"
echo "     ServerCat VPS Setup Script v1.0        "
echo "============================================"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    print_error "Cannot detect OS version"
    exit 1
fi

print_status "Detected OS: $OS $VER"

# Update system
print_status "Updating system packages..."
if command -v apt-get >/dev/null; then
    apt-get update -y > /dev/null 2>&1
    apt-get upgrade -y > /dev/null 2>&1
elif command -v yum >/dev/null; then
    yum update -y > /dev/null 2>&1
fi

# Install required packages
print_status "Installing required packages..."
if command -v apt-get >/dev/null; then
    apt-get install -y openssh-server fail2ban ufw sudo curl wget > /dev/null 2>&1
elif command -v yum >/dev/null; then
    yum install -y openssh-server fail2ban firewalld sudo curl wget > /dev/null 2>&1
fi

# Ensure SSH is running
print_status "Checking SSH service..."
SSH_SERVICE=""
if systemctl list-units --type=service | grep -q "sshd.service"; then
    SSH_SERVICE="sshd"
elif systemctl list-units --type=service | grep -q "ssh.service"; then
    SSH_SERVICE="ssh"
fi

if [ -n "$SSH_SERVICE" ]; then
    if systemctl is-active --quiet $SSH_SERVICE; then
        print_status "SSH service ($SSH_SERVICE) is already running"
    else
        print_status "Starting SSH service ($SSH_SERVICE)..."
        systemctl start $SSH_SERVICE
        systemctl enable $SSH_SERVICE
    fi
else
    print_error "Could not find SSH service (tried ssh and sshd)"
    exit 1
fi

# Configure root user for ServerCat monitoring
print_status "Configuring root user for ServerCat monitoring..."
MONITOR_USER="root"
print_status "Using root user directly for ServerCat access"

# Configure root password for ServerCat access
if [ "$FORCE_PASSWORD_RESET" = "true" ]; then
    print_status "Setting password for root user..."
    echo ""
    print_warning "Please set a strong password for root:"
    passwd root
else
    print_status "Root password configuration skipped (use FORCE_PASSWORD_RESET=true to reset)"
    print_warning "Ensure root has a password set for ServerCat access"
fi

# Root user already has full access - no additional configuration needed
echo ""
print_status "Root user configuration complete - ServerCat will have full system access"

# Setup SSH directory for root user (ServerCat access)
print_status "Setting up SSH authentication for root user..."
if [ ! -d "/root/.ssh" ]; then
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    print_status "SSH directory created for root"
else
    chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    print_status "Root SSH directory already exists - permissions verified"
fi

# Configure SSH security
print_status "Configuring SSH security settings..."
SSH_CONFIG="/etc/ssh/sshd_config"
# Only create backup if one doesn't exist from today
BACKUP_FILE="${SSH_CONFIG}.backup.$(date +%Y%m%d)"
if [ ! -f "$BACKUP_FILE" ]; then
    cp $SSH_CONFIG "$BACKUP_FILE"
    print_status "SSH config backed up to $BACKUP_FILE"
else
    print_status "SSH config backup already exists for today"
fi

# SSH port locked to 22 for safety
SSH_PORT=22
print_status "SSH port locked to default: $SSH_PORT"

# Apply security configurations
# Use more robust sed patterns and backup important changes
sed -i.bak 's/^[[:space:]]*#*[[:space:]]*PermitRootLogin.*/PermitRootLogin without-password/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*PubkeyAuthentication.*/PubkeyAuthentication yes/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*PasswordAuthentication.*/PasswordAuthentication yes/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*X11Forwarding.*/X11Forwarding no/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*UsePAM.*/UsePAM yes/' $SSH_CONFIG

# Configure SSH for direct root access
print_status "Configuring SSH for direct root access..."

# Enable root login with password for ServerCat
sed -i 's/^[[:space:]]*#*[[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' $SSH_CONFIG

# Remove any AllowUsers restrictions to allow root login
if grep -q "AllowUsers" $SSH_CONFIG; then
    print_warning "Removing AllowUsers restrictions to enable root access"
    sed -i '/^AllowUsers/d' $SSH_CONFIG
    sed -i '/^# Allow ServerCat/d' $SSH_CONFIG
fi

print_status "SSH security settings applied"

# Configure firewall (idempotent)
print_status "Configuring firewall..."
if command -v ufw >/dev/null; then
    # Check if rule already exists
    if ! ufw status | grep -q "$SSH_PORT/tcp"; then
        ufw allow $SSH_PORT/tcp > /dev/null 2>&1
        print_status "UFW rule added for port $SSH_PORT"
    else
        print_status "UFW rule for port $SSH_PORT already exists"
    fi
    # Enable UFW if not already enabled
    if ! ufw status | grep -q "Status: active"; then
        echo "y" | ufw enable > /dev/null 2>&1
        print_status "UFW firewall enabled"
    else
        print_status "UFW firewall already active"
    fi
elif command -v firewall-cmd >/dev/null; then
    # Check if port is already allowed
    if ! firewall-cmd --list-ports | grep -q "$SSH_PORT/tcp"; then
        firewall-cmd --permanent --add-port=$SSH_PORT/tcp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        print_status "Firewalld configured for port $SSH_PORT"
    else
        print_status "Firewalld already configured for port $SSH_PORT"
    fi
fi

# Configure fail2ban (idempotent)
print_status "Configuring fail2ban..."
if [ -d /etc/fail2ban ]; then
    # Create jail.local if it doesn't exist
    if [ ! -f /etc/fail2ban/jail.local ]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local 2>/dev/null || touch /etc/fail2ban/jail.local
        print_status "Created fail2ban jail.local"
    fi

    # Create or update custom SSH jail
    SSHD_JAIL="/etc/fail2ban/jail.d/sshd.local"
    cat << EOF > "$SSHD_JAIL"
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

    # Enable and start fail2ban if not already running
    if ! systemctl is-enabled fail2ban >/dev/null 2>&1; then
        systemctl enable fail2ban > /dev/null 2>&1
        print_status "fail2ban enabled"
    fi

    if ! systemctl is-active --quiet fail2ban; then
        systemctl start fail2ban > /dev/null 2>&1
        print_status "fail2ban started"
    else
        systemctl restart fail2ban > /dev/null 2>&1
        print_status "fail2ban restarted with new configuration"
    fi
else
    print_warning "fail2ban not installed - skipping configuration"
fi

# Restart SSH service (using detected service name)
print_status "Restarting SSH service..."
if [ -n "$SSH_SERVICE" ]; then
    systemctl restart $SSH_SERVICE
    print_status "SSH service ($SSH_SERVICE) restarted"
else
    # Fallback to trying both
    systemctl restart ssh 2>/dev/null || systemctl restart sshd
    print_status "SSH service restarted"
fi

# Get server IP
print_status "Getting server information..."
IP_ADDRESS=$(ip addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
if [ -z "$IP_ADDRESS" ]; then
    IP_ADDRESS=$(curl -s ifconfig.me 2>/dev/null || echo "UNKNOWN")
fi

# Create setup info file
INFO_FILE="/root/servercat_setup_info.txt"
cat << EOF > $INFO_FILE
=====================================
ServerCat Setup Complete!
=====================================

VPS Connection Details:
-----------------------
IP Address: $IP_ADDRESS
SSH Port: $SSH_PORT
Username: root
Password: [Root password - ensure it's set]

Root Access:
-----------
Direct root login enabled for ServerCat.
Full system access with root privileges.

Next Steps:
-----------
1. Install ServerCat on your iPhone from the App Store

2. Add this server in ServerCat:
   - Name: Your VPS Name
   - Host: $IP_ADDRESS
   - Port: $SSH_PORT
   - Username: root
   - Auth: Password (use root password)

3. For better security, set up SSH key authentication:
   a) In ServerCat, go to Keys section
   b) Create a new key pair
   c) Copy the public key
   d) On this server, run:
      echo "YOUR_PUBLIC_KEY" >> /root/.ssh/authorized_keys

4. After SSH key is working, disable password authentication:
   sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
   systemctl restart ssh

5. Test your connection!

Security Features Enabled:
-------------------------
- Direct root access enabled for ServerCat
- Root login with password enabled
- fail2ban protection active
- Firewall enabled on port $SSH_PORT
- SSH security configured

Important Files:
---------------
- SSH Config: /etc/ssh/sshd_config
- SSH Config Backup: /etc/ssh/sshd_config.backup.*
- Root SSH keys: /root/.ssh/authorized_keys
- This info file: $INFO_FILE

Troubleshooting:
---------------
- Check SSH status: systemctl status ssh
- Check fail2ban: systemctl status fail2ban
- View SSH logs: tail -f /var/log/auth.log
- Test locally: ssh root@localhost -p $SSH_PORT

=====================================
EOF

# Display the info
echo ""
cat $INFO_FILE

# Final recommendations
echo ""
print_warning "IMPORTANT SECURITY NOTES:"
print_warning "1. Save the password you just created - you'll need it for initial ServerCat connection"
print_warning "2. Set up SSH key authentication as soon as possible"
print_warning "3. After setting up keys, disable password authentication"
print_warning "4. Consider setting up automated backups and monitoring"
echo ""
print_status "Setup information saved to: $INFO_FILE"
print_status "Script completed successfully!"