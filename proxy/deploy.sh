#!/bin/bash
set -euo pipefail

# Deploy ladder-proxy to VM1 and configure nginx on web server
VM1="ghost-vm1"
WEB="ghost-web"
VM1_IP="83.136.251.162"

echo "=== Step 1: Deploy proxy to VM1 ==="

# Copy files
scp ladder_proxy.py requirements.txt ladder-proxy.service "$VM1:/tmp/"

ssh "$VM1" bash <<'REMOTE_VM1'
set -euo pipefail

# Create directory
sudo mkdir -p /opt/ghost/ladder-proxy
sudo cp /tmp/ladder_proxy.py /tmp/requirements.txt /opt/ghost/ladder-proxy/
sudo chown -R ghost:ghost /opt/ghost/ladder-proxy

# Create venv and install deps
if [ ! -d /opt/ghost/ladder-proxy/venv ]; then
    sudo -u ghost python3 -m venv /opt/ghost/ladder-proxy/venv
fi
sudo -u ghost /opt/ghost/ladder-proxy/venv/bin/pip install -q -r /opt/ghost/ladder-proxy/requirements.txt

# Install service
sudo cp /tmp/ladder-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ladder-proxy
sudo systemctl restart ladder-proxy

# Allow port 8801 from web server only
sudo ufw allow from 83.136.255.218 to any port 8801 proto tcp comment "ladder-proxy from web" 2>/dev/null || true

sleep 2
sudo systemctl status ladder-proxy --no-pager | head -10
echo "VM1 proxy deployed."
REMOTE_VM1

echo ""
echo "=== Step 2: Configure nginx on web server ==="

ssh "$WEB" bash <<REMOTE_WEB
set -euo pipefail

# Check if ladder location already exists
if sudo grep -q 'ladder' /etc/nginx/sites-enabled/bitcoinghost; then
    echo "Ladder proxy location already configured in nginx."
else
    # Add location block before the closing } of the SSL server block
    sudo sed -i '/location ~\* \\\.\(jpg/i\\
    # Ladder Script Signet Proxy\\
    location /api/ladder/ {\\
        proxy_pass http://${VM1_IP}:8801;\\
        proxy_set_header Host \\\$host;\\
        proxy_set_header X-Real-IP \\\$remote_addr;\\
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;\\
        proxy_set_header X-Forwarded-Proto \\\$scheme;\\
        proxy_read_timeout 30s;\\
        proxy_connect_timeout 5s;\\
    }\\
' /etc/nginx/sites-enabled/bitcoinghost
    sudo nginx -t && sudo systemctl reload nginx
    echo "Nginx configured."
fi
REMOTE_WEB

echo ""
echo "=== Done ==="
echo "Test: curl -s https://bitcoinghost.org/api/ladder/status"
