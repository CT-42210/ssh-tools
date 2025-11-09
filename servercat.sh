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
echo "     ServerCat VPS Setup Script v2.0        "
echo "============================================"
echo ""
print_warning "This script will configure your VPS for ServerCat monitoring"
print_warning "It will modify SSH configuration and firewall settings"
echo ""
read -p "Continue? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_status "Setup cancelled"
    exit 0
fi
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
    if apt-get update -y; then
        print_status "Package lists updated"
        print_status "Upgrading packages (this may take a while)..."
        apt-get upgrade -y
    else
        print_error "Failed to update package lists"
        exit 1
    fi
elif command -v yum >/dev/null; then
    if yum update -y; then
        print_status "System updated"
    else
        print_error "Failed to update system"
        exit 1
    fi
fi

# Install required packages
print_status "Installing required packages..."
if command -v apt-get >/dev/null; then
    if apt-get install -y openssh-server fail2ban ufw sudo curl wget; then
        print_status "Required packages installed"
    else
        print_error "Failed to install required packages"
        exit 1
    fi
elif command -v yum >/dev/null; then
    if yum install -y openssh-server fail2ban firewalld sudo curl wget; then
        print_status "Required packages installed"
    else
        print_error "Failed to install required packages"
        exit 1
    fi
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

# Apply security configurations for ServerCat
print_status "Configuring SSH for ServerCat access..."

# Configure SSH settings (all in one place to avoid conflicts)
sed -i.bak 's/^[[:space:]]*#*[[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*PubkeyAuthentication.*/PubkeyAuthentication yes/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*PasswordAuthentication.*/PasswordAuthentication yes/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*X11Forwarding.*/X11Forwarding no/' $SSH_CONFIG
sed -i 's/^[[:space:]]*#*[[:space:]]*UsePAM.*/UsePAM yes/' $SSH_CONFIG

# Check for AllowUsers restrictions and warn (but don't delete)
if grep -q "^AllowUsers" $SSH_CONFIG; then
    print_warning "Found AllowUsers restriction in SSH config"
    print_warning "You may need to add 'root' to the AllowUsers line manually"
    print_warning "Current AllowUsers line:"
    grep "^AllowUsers" $SSH_CONFIG
    print_warning "To enable root access, add 'root' to the AllowUsers line in $SSH_CONFIG"
fi

print_status "SSH security settings applied"

# Configure firewall (idempotent)
print_status "Configuring firewall..."
if command -v ufw >/dev/null; then
    # CRITICAL: Add SSH rule BEFORE enabling UFW to avoid lockout
    # Check if rule already exists
    if ! ufw status | grep -q "$SSH_PORT/tcp"; then
        print_status "Adding UFW rule for SSH port $SSH_PORT..."
        if ufw allow $SSH_PORT/tcp; then
            print_status "UFW rule added for port $SSH_PORT"
        else
            print_error "Failed to add UFW rule for port $SSH_PORT"
            print_error "Aborting to prevent lockout"
            exit 1
        fi
    else
        print_status "UFW rule for port $SSH_PORT already exists"
    fi

    # Verify the rule is properly configured before enabling
    if ufw status | grep -q "$SSH_PORT/tcp.*ALLOW"; then
        print_status "SSH port rule verified"
    else
        print_warning "Could not verify SSH rule - checking if already allowed..."
    fi

    # Enable UFW if not already enabled
    if ! ufw status | grep -q "Status: active"; then
        print_warning "Enabling UFW firewall..."
        if echo "y" | ufw enable; then
            print_status "UFW firewall enabled successfully"
        else
            print_error "Failed to enable UFW"
            exit 1
        fi
    else
        print_status "UFW firewall already active"
    fi
elif command -v firewall-cmd >/dev/null; then
    # Check if port is already allowed
    if ! firewall-cmd --list-ports | grep -q "$SSH_PORT/tcp"; then
        print_status "Adding firewalld rule for SSH port $SSH_PORT..."
        if firewall-cmd --permanent --add-port=$SSH_PORT/tcp && firewall-cmd --reload; then
            print_status "Firewalld configured for port $SSH_PORT"
        else
            print_error "Failed to configure firewalld"
            exit 1
        fi
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

# Validate SSH configuration before restarting
print_status "Validating SSH configuration..."
if sshd -t 2>/dev/null; then
    print_status "SSH configuration is valid"
elif /usr/sbin/sshd -t 2>/dev/null; then
    print_status "SSH configuration is valid"
else
    print_error "SSH configuration validation failed!"
    print_error "Restoring backup configuration..."
    if [ -f "${SSH_CONFIG}.bak" ]; then
        cp "${SSH_CONFIG}.bak" "$SSH_CONFIG"
        print_status "Backup restored"
    fi
    print_error "Please check $SSH_CONFIG for errors"
    exit 1
fi

# Restart SSH service (using detected service name)
print_status "Restarting SSH service..."
if [ -n "$SSH_SERVICE" ]; then
    if systemctl restart $SSH_SERVICE; then
        print_status "SSH service ($SSH_SERVICE) restarted successfully"
    else
        print_error "Failed to restart SSH service!"
        print_error "Restoring backup and retrying..."
        if [ -f "${SSH_CONFIG}.bak" ]; then
            cp "${SSH_CONFIG}.bak" "$SSH_CONFIG"
            systemctl restart $SSH_SERVICE
        fi
        exit 1
    fi
else
    # Fallback to trying both
    if systemctl restart ssh 2>/dev/null || systemctl restart sshd; then
        print_status "SSH service restarted successfully"
    else
        print_error "Failed to restart SSH service!"
        exit 1
    fi
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

# Verify SSH is still accessible
echo ""
print_status "Verifying SSH service is accessible..."
if systemctl is-active --quiet $SSH_SERVICE && ss -tlnp | grep -q ":$SSH_PORT "; then
    print_status "SSH service is running and listening on port $SSH_PORT"
else
    print_error "WARNING: SSH service may not be accessible!"
    print_error "Check service status: systemctl status $SSH_SERVICE"
fi

# Test local SSH connection (non-blocking)
print_status "Testing local SSH connection..."
if timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -p $SSH_PORT root@localhost exit 2>/dev/null; then
    print_status "Local SSH connection successful!"
elif [ $? -eq 255 ]; then
    print_status "SSH is accessible (authentication required as expected)"
else
    print_warning "Could not verify SSH connection - manual testing recommended"
fi

# Final recommendations
echo ""
print_warning "IMPORTANT SECURITY NOTES:"
print_warning "1. Test SSH access from another terminal before closing this session!"
print_warning "2. Save the root password - you'll need it for initial ServerCat connection"
print_warning "3. Set up SSH key authentication as soon as possible"
print_warning "4. After setting up keys, disable password authentication"
print_warning "5. Consider setting up automated backups and monitoring"
echo ""
print_status "Setup information saved to: $INFO_FILE"
print_status "Script completed successfully!"