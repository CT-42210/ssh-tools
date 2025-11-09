#!/bin/bash

# SSH Key Setup Script
# Run this on your LOCAL machine to set up SSH key authentication with a new server

set -e

# Cleanup function - removes SSH config entry if script fails
cleanup() {
    if [ $? -ne 0 ] && [ -n "$ALIAS_NAME" ] && [ -n "$SSH_CONFIG" ]; then
        if grep -q "^Host $ALIAS_NAME$" "$SSH_CONFIG" 2>/dev/null; then
            echo ""
            echo -e "${YELLOW}[*]${NC} Cleaning up failed configuration..."
            # Remove the failed SSH config entry
            sed -i.bak "/^Host $ALIAS_NAME$/,/^$/d" "$SSH_CONFIG"
            echo -e "${BLUE}[i]${NC} Removed incomplete SSH config entry for '$ALIAS_NAME'"
        fi
    fi
}

trap cleanup EXIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Header
echo "============================================"
echo "     SSH Key Setup Script                   "
echo "============================================"
echo ""

# Check if SSH key exists, generate if not
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_PUB_KEY="$HOME/.ssh/id_ed25519.pub"

if [ -f "$SSH_KEY" ]; then
    print_status "SSH key already exists: $SSH_KEY"
    print_info "Public key:"
    cat "$SSH_PUB_KEY"
    echo ""
else
    print_warning "No SSH key found at $SSH_KEY"
    echo ""
    read -p "Generate a new ED25519 SSH key? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        read -p "Enter your email for the key comment (default: $(whoami)@$(hostname)): " EMAIL
        if [ -z "$EMAIL" ]; then
            EMAIL="$(whoami)@$(hostname)"
        fi

        print_status "Generating new ED25519 SSH key..."
        ssh-keygen -t ed25519 -f "$SSH_KEY" -C "$EMAIL"
        print_status "SSH key generated successfully!"
        echo ""
    else
        print_error "Cannot proceed without an SSH key"
        exit 1
    fi
fi

# Get server details
echo ""
print_info "Enter server details:"
echo ""

read -p "Server IP address or hostname: " SERVER_HOST
if [ -z "$SERVER_HOST" ]; then
    print_error "Server address is required"
    exit 1
fi

read -p "Username (default: root): " SERVER_USER
SERVER_USER=${SERVER_USER:-root}

read -p "SSH port (default: 22): " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-22}

read -p "Friendly alias name (e.g., 'my-vps', 'prod-server'): " ALIAS_NAME
if [ -z "$ALIAS_NAME" ]; then
    ALIAS_NAME=$(echo "$SERVER_HOST" | tr '.' '-')
    print_warning "No alias provided, using: $ALIAS_NAME"
fi

# Check if alias already exists and clean it up FIRST
SSH_CONFIG="$HOME/.ssh/config"
if grep -q "^Host $ALIAS_NAME$" "$SSH_CONFIG" 2>/dev/null; then
    echo ""
    print_warning "Alias '$ALIAS_NAME' already exists in SSH config"
    print_info "This may be from a previous failed setup attempt"
    read -p "Remove existing entry and start fresh? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        # Remove existing entry (including all lines until next Host or EOF)
        sed -i.bak "/^Host $ALIAS_NAME$/,/^Host /{ /^Host $ALIAS_NAME$/d; /^Host /!d; }" "$SSH_CONFIG"
        print_status "Removed old entry"
    else
        print_warning "Setup cancelled - cannot proceed with existing alias"
        exit 0
    fi
fi

# Summary
echo ""
print_info "Configuration Summary:"
echo "  Alias:    $ALIAS_NAME"
echo "  Host:     $SERVER_HOST"
echo "  User:     $SERVER_USER"
echo "  Port:     $SERVER_PORT"
echo "  Key:      $SSH_KEY"
echo ""

read -p "Proceed with setup? (Y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    print_warning "Setup cancelled"
    exit 0
fi

# Copy SSH key to server
echo ""
print_status "Copying SSH key to server..."
print_warning "You will be prompted for the server password"
echo ""

# Use StrictHostKeyChecking=accept-new to auto-accept new hosts (but not changed ones)
if ssh-copy-id -i "$SSH_PUB_KEY" -o StrictHostKeyChecking=accept-new -o Port="$SERVER_PORT" "$SERVER_USER@$SERVER_HOST"; then
    print_status "SSH key copied successfully!"
else
    print_error "Failed to copy SSH key to server"
    exit 1
fi

# Add to SSH config
echo ""
print_status "Adding server to SSH config..."

# Ensure SSH config exists
touch "$SSH_CONFIG"
chmod 600 "$SSH_CONFIG"

# Add new entry
cat << EOF >> "$SSH_CONFIG"

Host $ALIAS_NAME
    HostName $SERVER_HOST
    User $SERVER_USER
    Port $SERVER_PORT
    IdentityFile $SSH_KEY
EOF

print_status "Server added to SSH config"

# Test connection
echo ""
print_status "Testing connection..."
echo ""

if ssh -o ConnectTimeout=10 -o BatchMode=yes "$ALIAS_NAME" "echo 'Connection successful!'" 2>/dev/null; then
    print_status "Connection test successful!"
else
    print_warning "Connection test failed, but key may still be configured"
    print_info "Try manually: ssh $ALIAS_NAME"
fi

# Final summary
echo ""
echo "============================================"
print_status "Setup Complete!"
echo "============================================"
echo ""
print_info "You can now connect using:"
echo "  ssh $ALIAS_NAME"
echo ""
print_info "Your SSH config: $SSH_CONFIG"
print_info "Your public key: $SSH_PUB_KEY"
echo ""
print_warning "Security recommendations:"
echo "  1. Test the connection: ssh $ALIAS_NAME"
echo "  2. Once working, disable password auth on server:"
echo "     ssh $ALIAS_NAME 'sudo sed -i \"s/^#*PasswordAuthentication.*/PasswordAuthentication no/\" /etc/ssh/sshd_config && sudo systemctl restart sshd'"
echo "  3. Keep your private key secure and backed up"
echo ""
