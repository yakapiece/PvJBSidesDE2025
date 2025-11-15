#!/bin/bash
# C2 Server Automated Setup Script
# =================================
# 
# This script automatically configures a C2 server with Covenant framework
# for red team exercises. It includes security hardening and monitoring.
#
# Author: Manus AI
# Purpose: Educational demonstration of automated C2 server deployment

set -e

# Variables passed from Terraform
ADMIN_PASSWORD="${admin_password}"
DOMAIN_NAME="${domain_name}"

# Logging setup
exec > >(tee -a /var/log/c2-setup.log)
exec 2>&1

echo "=== C2 Server Setup Started at $(date) ==="

# Update system
echo "Updating system packages..."
apt-get update -y
apt-get upgrade -y

# Install required packages
echo "Installing required packages..."
apt-get install -y \
    docker.io \
    docker-compose \
    nginx \
    certbot \
    python3-certbot-nginx \
    ufw \
    fail2ban \
    htop \
    curl \
    wget \
    git \
    unzip \
    jq \
    awscli

# Configure firewall
echo "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 7443/tcp  # Covenant web interface
ufw --force enable

# Configure fail2ban
echo "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Create C2 user
echo "Creating C2 user..."
useradd -m -s /bin/bash c2operator
echo "c2operator:$ADMIN_PASSWORD" | chpasswd
usermod -aG docker c2operator

# Setup Covenant C2 Framework
echo "Setting up Covenant C2 Framework..."
cd /opt
git clone --recurse-submodules https://github.com/cobbr/Covenant.git
cd Covenant/Covenant

# Create Covenant configuration
cat > appsettings.json << EOF
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=Data/covenant.db"
  },
  "CovenantUrl": "https://0.0.0.0:7443",
  "CovenantBindUrl": "https://0.0.0.0:7443"
}
EOF

# Build and setup Covenant
echo "Building Covenant..."
docker build -t covenant .

# Create systemd service for Covenant
cat > /etc/systemd/system/covenant.service << EOF
[Unit]
Description=Covenant C2 Framework
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=c2operator
WorkingDirectory=/opt/Covenant/Covenant
ExecStart=/usr/bin/docker run --rm -it -p 7443:7443 -p 80:80 -p 443:443 -v /opt/Covenant/Covenant/Data:/app/Data covenant --username CovenantAdmin --computername 0.0.0.0 --password $ADMIN_PASSWORD
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure nginx as reverse proxy
echo "Configuring nginx..."
cat > /etc/nginx/sites-available/c2-proxy << EOF
server {
    listen 80;
    server_name $DOMAIN_NAME;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 443 ssl;
    server_name $DOMAIN_NAME;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    
    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_ssl_verify off;
    }
}
EOF

ln -sf /etc/nginx/sites-available/c2-proxy /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Setup SSL certificate (self-signed for now)
echo "Setting up SSL certificate..."
mkdir -p /etc/ssl/private
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/c2-selfsigned.key \
    -out /etc/ssl/certs/c2-selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN_NAME"

# Configure log rotation
echo "Configuring log rotation..."
cat > /etc/logrotate.d/c2-server << EOF
/var/log/c2-setup.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

# Setup monitoring script
echo "Setting up monitoring..."
cat > /usr/local/bin/c2-monitor.sh << 'EOF'
#!/bin/bash
# C2 Server Monitoring Script

LOG_FILE="/var/log/c2-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Check Covenant service
if systemctl is-active --quiet covenant; then
    echo "[$DATE] Covenant service: RUNNING" >> $LOG_FILE
else
    echo "[$DATE] Covenant service: STOPPED - Attempting restart" >> $LOG_FILE
    systemctl restart covenant
fi

# Check nginx service
if systemctl is-active --quiet nginx; then
    echo "[$DATE] Nginx service: RUNNING" >> $LOG_FILE
else
    echo "[$DATE] Nginx service: STOPPED - Attempting restart" >> $LOG_FILE
    systemctl restart nginx
fi

# Check disk space
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "[$DATE] WARNING: Disk usage at ${DISK_USAGE}%" >> $LOG_FILE
fi

# Check memory usage
MEM_USAGE=$(free | awk 'NR==2{printf "%.2f", $3*100/$2}')
if (( $(echo "$MEM_USAGE > 80" | bc -l) )); then
    echo "[$DATE] WARNING: Memory usage at ${MEM_USAGE}%" >> $LOG_FILE
fi
EOF

chmod +x /usr/local/bin/c2-monitor.sh

# Setup cron job for monitoring
echo "*/5 * * * * /usr/local/bin/c2-monitor.sh" | crontab -

# Create startup script
cat > /usr/local/bin/c2-startup.sh << EOF
#!/bin/bash
# C2 Server Startup Script

echo "Starting C2 infrastructure..."

# Start services
systemctl start docker
systemctl start nginx
systemctl start covenant

# Wait for services to be ready
sleep 30

# Log startup
echo "$(date): C2 infrastructure started" >> /var/log/c2-startup.log
EOF

chmod +x /usr/local/bin/c2-startup.sh

# Enable services
echo "Enabling services..."
systemctl enable docker
systemctl enable nginx
systemctl enable covenant

# Start services
echo "Starting services..."
systemctl start docker
systemctl start nginx

# Create deployment info file
cat > /opt/deployment-info.json << EOF
{
    "deployment_time": "$(date -Iseconds)",
    "c2_framework": "Covenant",
    "domain": "$DOMAIN_NAME",
    "admin_user": "CovenantAdmin",
    "web_interface": "https://$DOMAIN_NAME:7443",
    "services": {
        "covenant": "port 7443",
        "http_listener": "port 80",
        "https_listener": "port 443"
    }
}
EOF

# Set proper permissions
chown -R c2operator:c2operator /opt/Covenant
chmod 600 /opt/deployment-info.json

echo "=== C2 Server Setup Completed at $(date) ==="
echo "Covenant web interface will be available at: https://$DOMAIN_NAME:7443"
echo "Default credentials: CovenantAdmin / $ADMIN_PASSWORD"
echo "Setup log available at: /var/log/c2-setup.log"

