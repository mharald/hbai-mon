#!/bin/bash

# HBAI-MON Installation Script
# Consolidates all files in /etc/hbai-mon

set -e

echo "Installing HBAI-MON v3.0..."

# Create directory structure
mkdir -p /etc/hbai-mon

# Set proper permissions
chmod 700 /etc/hbai-mon

# Make scripts executable
chmod +x /etc/hbai-mon/hbai-mon.py
chmod +x /etc/hbai-mon/hbai_ollama.py
chmod +x /etc/hbai-mon/hbai_executor.py

# Secure credentials file
if [ -f /etc/hbai-mon/.credentials ]; then
    chmod 600 /etc/hbai-mon/.credentials
fi

# Create symlink for easy execution
ln -sf /etc/hbai-mon/hbai-mon.py /usr/local/bin/hbai-mon

# Setup log rotation
cat > /etc/logrotate.d/hbai-mon << EOF
/etc/hbai-mon/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF

echo "HBAI-MON installed successfully!"
echo "Run 'hbai-mon' to start monitoring"
