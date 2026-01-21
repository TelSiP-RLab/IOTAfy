IOTAfy Devices Management Platform — Installation Guide

Contents
1. Prerequisites
2. Obtain/Place Files
3. PHP Configuration
4. Database Initialization (SQLite)
5. Permissions/Directories (logs, firmware, database)
6. Environment Variables (IOTAFY_APP_KEY)
7. Web Server Setup (Apache/Nginx/IIS)
8. Enable HTTPS & Security Headers
9. Initial Application Setup
10. Device Endpoints
11. Backup & Maintenance
12. Upgrade / Migration
13. Troubleshooting

────────────────────────────────────────────────────────────────────────────
1) Prerequisites
- PHP 8.0+ with extensions: pdo_sqlite, openssl, curl, mbstring, json
- Web Server: Apache or Nginx (Linux) / IIS or Apache (Windows)
- PHP via PHP-FPM or mod_php (Apache) / FastCGI (IIS)
- SQLite (embedded). The sqlite3 CLI tool is optional but handy for dumps
- Network/Firewall access to the web server and (if needed) from server to devices

Check PHP extensions (Linux):
php -m | grep -E "pdo_sqlite|openssl|curl|mbstring|json"

────────────────────────────────────────────────────────────────────────────
2) Obtain/Place Files
- Copy the project files into your web root, e.g.:
  - Linux: /var/www/devices
  - Windows (IIS): C:\inetpub\wwwroot\devices
  - Windows (Apache XAMPP): C:\xampp\htdocs\devices

────────────────────────────────────────────────────────────────────────────
3) PHP Configuration
- Recommended php.ini settings (adjust as needed):
  - session.cookie_samesite = Lax (or Strict if no cross-site flows)
  - session.cookie_httponly = On
  - session.cookie_secure = On (in production with HTTPS)
  - upload_max_filesize = 16M (or higher per firmware size)
  - post_max_size = 32M (always ≥ upload_max_filesize)
  - expose_php = Off

────────────────────────────────────────────────────────────────────────────
4) Database Initialization (SQLite)
- The database file is device_info.db in the project root.
- If it does not exist, create it from schema.sql.

Linux:
cd /var/www/devices
sqlite3 device_info.db < schema.sql

Windows (PowerShell, sqlite3.exe in PATH):
cd C:\inetpub\wwwroot\devices
sqlite3 device_info.db ".read schema.sql"

Note: The app performs a lazy migration for 2FA columns when needed.

────────────────────────────────────────────────────────────────────────────
5) Permissions/Directories (logs, firmware, database)
- Ensure the directories exist: logs/, firmware/
- The web server must have write access to: logs/, firmware/ and device_info.db (or the directory to create it if missing).

Linux (Apache/Nginx user www-data):
sudo chown -R www-data:www-data /var/www/devices
sudo chmod -R 750 /var/www/devices
sudo mkdir -p /var/www/devices/logs /var/www/devices/firmware
sudo chmod 770 /var/www/devices/logs /var/www/devices/firmware

Windows:
- Grant Modify/Write to the Application Pool user (IIS) or Apache service user for logs/, firmware/ and device_info.db

────────────────────────────────────────────────────────────────────────────
6) Environment Variables (IOTAFY_APP_KEY)
- The app encrypts sensitive data (e.g., 2FA secret) using AES-256-GCM.
- Set IOTAFY_APP_KEY to a secure 32-byte value. It may be raw or base64 (with prefix base64:).

Linux (bash):
export IOTAFY_APP_KEY="base64:$(openssl rand -base64 32)"
# Persist it via /etc/environment or your service unit, then restart the web server

Windows (PowerShell):
# Generate a base64-encoded 32-byte key
$bytes = 1..32 | ForEach-Object { Get-Random -Max 256 }
$env:IOTAFY_APP_KEY = "base64:" + [Convert]::ToBase64String([byte[]]$bytes)
# Set as a System/User Environment Variable via GUI or setx for permanence

After setting the variable:
- Restart your web server so PHP workers inherit the environment.

────────────────────────────────────────────────────────────────────────────
7) Web Server Setup

Apache (virtual host example):
<VirtualHost *:80>
    ServerName your-domain.example
    DocumentRoot /var/www/devices

    <Directory /var/www/devices>
        AllowOverride All
        Require all granted
        Options -Indexes
    </Directory>

    # Optional: redirect to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]
</VirtualHost>

Nginx (server block example):
server {
    listen 80;
    server_name your-domain.example;

    root /var/www/devices;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock; # adjust path
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_read_timeout 300;
    }

    # Optional redirect to HTTPS
    return 301 https://$host$request_uri;
}

IIS:
- Add a site/virtual directory to the project folder
- Enable PHP via FastCGI
- Use URL Rewrite to enforce HTTPS if SSL is configured

────────────────────────────────────────────────────────────────────────────
8) Enable HTTPS & Security Headers
- Enable TLS (Let’s Encrypt or corporate CA)
- Consider HSTS (Strict-Transport-Security)
- Add security headers at the web server level:
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - Referrer-Policy: no-referrer
  - Content-Security-Policy (CSP): whitelist your CDNs (Bootstrap, FontAwesome, jQuery, Chart.js). Example (minimal, adjust):
    Content-Security-Policy: default-src 'self'; img-src 'self' data: https://chart.googleapis.com https://api.qrserver.com; script-src 'self' https://code.jquery.com https://stackpath.bootstrapcdn.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; connect-src 'self'; frame-ancestors 'none';

────────────────────────────────────────────────────────────────────────────
9) Initial Application Setup
- Create an admin user:
  - The reset_admin.php script is a CLI-only tool that creates/resets the admin user with default credentials.
  
  **Important**: The script can ONLY be run from command line (CLI), not from a web browser, for security reasons.
  
  Linux:
    cd /var/www/devices
    php reset_admin.php
  
  Windows (PowerShell):
    cd C:\inetpub\wwwroot\devices
    php reset_admin.php
  
  The script will:
    - Create/reset the admin user with:
      * Username: admin
      * Password: admin
      * Role: admin
      * 2FA: Disabled
    - Log the execution to the log file
  
  **Important**: After first login, immediately change the password from the admin panel for security.
  
  - Alternatively: Insert an admin row into users via SQLite GUI/CLI. Passwords must be created with password_hash() (use a small PHP snippet or the change password feature)
- Log in at login.php
- Optionally enable 2FA on profile.php (requires IOTAFY_APP_KEY)
- Create users, groups, assign devices
- Adjust EMAIL_FROM/EMAIL_SUBJECT in config.inc if you plan to send emails

────────────────────────────────────────────────────────────────────────────
10) Device Endpoints
- Endpoints such as server.php, ping.php require a user authkey
- Ensure each device knows the correct authkey (profile.php → Regenerate Authkey for the owning user)
- Each request validates with: SELECT id FROM users WHERE authkey = :authkey
- Use HTTPS and firewall restrictions where possible

────────────────────────────────────────────────────────────────────────────
11) Backup & Maintenance
- SQLite backup (Linux):
  - Use backup.sh or your own cron job
  - Example cron (daily at 03:30):
    30 3 * * * cd /var/www/devices && ./backup.sh >> logs/server.log 2>&1
- Device monitoring (Linux):
  - To automatically monitor device status, add a cron job that runs monitor_devices.php regularly (e.g., every minute)
  - Example cron (every minute):
    */1 * * * * echo "\n==== $(date '+\%Y-\%m-\%d \%H:\%M:\%S') ====" >> /path/to/devices/logs/monitor.log && /usr/bin/php /path/to/devices/monitor_devices.php >> /path/to/devices/logs/monitor.log 2>&1
  - Specific example (adjust paths):
    */1 * * * * echo "\n==== $(date '+\%Y-\%m-\%d \%H:\%M:\%S') ====" >> /home/protontech/web/icp.protontech.gr/public_html/devices/logs/monitor.log && /usr/bin/php /home/protontech/web/icp.protontech.gr/public_html/devices/monitor_devices.php >> /home/protontech/web/icp.protontech.gr/public_html/devices/logs/monitor.log 2>&1
  - Note: Replace /path/to/devices with your actual project path and /usr/bin/php with your PHP executable path (find with: which php)
- Device monitoring (Windows):
  - To automatically monitor device status on Windows, use Task Scheduler
  - Method 1: PowerShell Script + Task Scheduler
    1. Create a PowerShell script monitor_devices.ps1:
       $logFile = "C:\inetpub\wwwroot\devices\logs\monitor.log"
       $phpPath = "C:\php\php.exe"  # Adjust PHP path
       $scriptPath = "C:\inetpub\wwwroot\devices\monitor_devices.php"  # Adjust script path
       $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
       Add-Content -Path $logFile -Value "`n==== $timestamp ===="
       & $phpPath $scriptPath | Add-Content -Path $logFile
    2. Create Scheduled Task:
       - Open Task Scheduler
       - Click Create Basic Task
       - Name: "Monitor Devices"
       - Trigger: Daily → Select "Repeat task every: 1 minute" for 24 hours
       - Action: Start a program
       - Program: powershell.exe
       - Arguments: -ExecutionPolicy Bypass -File "C:\inetpub\wwwroot\devices\monitor_devices.ps1"
  - Method 2: Direct Task Scheduler (without script)
    1. Create Scheduled Task:
       - Program: C:\php\php.exe (adjust path)
       - Arguments: C:\inetpub\wwwroot\devices\monitor_devices.php >> C:\inetpub\wwwroot\devices\logs\monitor.log 2>&1
       - Trigger: Daily → Repeat task every: 1 minute for 24 hours
  - Alternative: Use schtasks command line:
    schtasks /create /tn "Monitor Devices" /tr "C:\php\php.exe C:\inetpub\wwwroot\devices\monitor_devices.php >> C:\inetpub\wwwroot\devices\logs\monitor.log 2>&1" /sc minute /mo 1 /f
  - Note: On Windows, to run every minute, set the trigger as Daily with repetition every 1 minute
- Windows (Backup): Use Task Scheduler with a PowerShell script calling sqlite3 ".dump" and store timestamped files
- Logs: Monitor logs/server.log and logs/monitor.log. The app performs daily/size-based rotation

────────────────────────────────────────────────────────────────────────────
12) Upgrade / Migration
- Backup device_info.db and the firmware/ and logs/ folders
- Copy the new app files to the target
- Verify permissions, IOTAFY_APP_KEY and PHP extensions
- Apply any SQL changes if needed. The app lazily checks 2FA columns; for new objects, run updated schema/migrations
- Smoke test: login, dashboard, device_management, upload/restore firmware, monitor_status

────────────────────────────────────────────────────────────────────────────
13) Troubleshooting
- Login issues:
  - Verify the user exists and the password hash is correct
  - Check login_attempts for lockout; wait or admin unlock
  - With 2FA enabled, ensure IOTAFY_APP_KEY is set and system time is synced (NTP)
- Encryption issues:
  - Ensure IOTAFY_APP_KEY is set and the web server was restarted
- Firmware upload fails:
  - Check permissions on firmware/
  - Increase upload_max_filesize and post_max_size in php.ini
- Device restart commands:
  - Check network reachability/ports and credentials. Avoid SSL_VERIFYPEER=false in production; prefer valid certificates
- 404/500 errors:
  - Check web server error logs and logs/server.log

Security Notes
- Always use HTTPS
- Enable HSTS and security headers
- Restrict admin URLs via firewall/VPN where feasible
- Keep keys and backups outside the web root with limited permissions
