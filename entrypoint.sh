#!/bin/sh
set -e

APP_DIR="/var/www/html"
cd "$APP_DIR"

# Ensure required directories exist
mkdir -p data logs firmware

# Configure msmtp from environment variables
# Ensure logs directory exists for msmtp logfile
mkdir -p "$APP_DIR/logs"
touch "$APP_DIR/logs/msmtp.log"
chmod 666 "$APP_DIR/logs/msmtp.log"

if [ -n "$SMTP_HOST" ]; then
  echo "Configuring msmtp with SMTP server: $SMTP_HOST"
  
  # Create msmtprc configuration
  cat > /etc/msmtprc <<EOF
# msmtp configuration (auto-generated from environment variables)
defaults
auth           ${SMTP_AUTH:-on}
tls            ${SMTP_TLS:-on}
tls_starttls   ${SMTP_STARTTLS:-on}
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/www/html/logs/msmtp.log
syslog         off

# Account settings
account        default
host           ${SMTP_HOST}
port           ${SMTP_PORT:-587}
from           ${SMTP_FROM:-no-reply@yourdomain.com}
EOF
  
  # Add user and password only if provided
  if [ -n "$SMTP_USER" ]; then
    echo "user           ${SMTP_USER}" >> /etc/msmtprc
  fi
  if [ -n "$SMTP_PASS" ]; then
    echo "password       ${SMTP_PASS}" >> /etc/msmtprc
  fi
  
  # Set proper permissions
  # msmtp prefers 600, but we need www-data (PHP) to be able to check if file exists
  # Use 640 (readable by group) and set group to www-data
  chmod 640 /etc/msmtprc
  chown root:www-data /etc/msmtprc
  
  # Verify configuration
  if [ -f /etc/msmtprc ]; then
    echo "msmtp configuration created successfully at /etc/msmtprc"
    echo "Configuration preview (without password):"
    sed 's/password.*/password [HIDDEN]/' /etc/msmtprc | head -15
  else
    echo "ERROR: Failed to create /etc/msmtprc"
  fi
else
  # SMTP_HOST not set - silently skip (email is only needed in monitor container)
  # Remove any existing broken config
  if [ -f /etc/msmtprc ]; then
    rm -f /etc/msmtprc
  fi
  # Don't output warnings - email is optional and only needed in iotafy_monitor
fi

# Test msmtp configuration
if command -v msmtp >/dev/null 2>&1; then
  if msmtp --version >/dev/null 2>&1; then
    echo "msmtp is installed and accessible"
    # Verify sendmail symlink
    if [ -L /usr/sbin/sendmail ] && [ -L /usr/bin/sendmail ]; then
      echo "sendmail symlinks are correctly configured"
    else
      echo "WARNING: sendmail symlinks may be missing"
    fi
  else
    echo "WARNING: msmtp command not working properly"
  fi
else
  echo "WARNING: msmtp command not found"
fi

# Create a test email script for easy testing
cat > /usr/local/bin/test-email.sh <<'TESTEOF'
#!/bin/sh
# Test email script for msmtp
if [ -z "$1" ]; then
  echo "Usage: test-email.sh recipient@example.com"
  exit 1
fi
echo "Test email from IOTAfy Platform" | msmtp -v "$1"
TESTEOF
chmod +x /usr/local/bin/test-email.sh
echo "Test email script created at /usr/local/bin/test-email.sh"

# Auto-generate IOTAFY_APP_KEY if not provided or left as placeholder
if [ -z "$IOTAFY_APP_KEY" ] || echo "$IOTAFY_APP_KEY" | grep -q "CHANGE_ME_GENERATE_A_REAL_KEY"; then
  echo "Generating random IOTAFY_APP_KEY..."
  if command -v php >/dev/null 2>&1; then
    if KEY=$(php -r '$bytes = random_bytes(32); echo "base64:".base64_encode($bytes);'); then
      IOTAFY_APP_KEY="$KEY"
      export IOTAFY_APP_KEY
    else
      echo "Warning: failed to generate IOTAFY_APP_KEY via php."
    fi
  else
    echo "Warning: php CLI not found, cannot auto-generate IOTAFY_APP_KEY."
  fi
fi

# Initialize SQLite database from schema.sql if it does not exist
if [ ! -f "data/device_info.db" ] && [ -f "schema.sql" ]; then
  echo "Initializing SQLite database at data/device_info.db..."
  sqlite3 "data/device_info.db" < "schema.sql" || echo "Warning: SQLite initialization failed."
fi

# Ensure correct ownership for runtime directories
chown -R www-data:www-data data logs firmware

exec "$@"

