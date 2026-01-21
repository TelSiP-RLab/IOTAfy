# IOTAfy Platform
An ESP32-Based OTA Firmware Management Platform for Scalable IoT Deployments 

## Description
IoT Device Management Platform with secure authentication and monitoring capabilities.

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Git
- OpenSSL (usually pre-installed on Linux/macOS)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/TelSiP-RLab/IOTAfy.git
   cd IOTAfy
   ```

2. **Configure environment**
   ```bash
   cp .env.template .env
   sed -i "s|^IOTAFY_APP_KEY=.*|IOTAFY_APP_KEY=base64:$(openssl rand -base64 32)|" .env
   ```

3. **Build and start containers**
   ```bash
   docker compose build
   docker compose up -d
   ```

4. **Initialize admin account**
   ```bash
   docker compose exec -it iotafy_platform php /var/www/html/reset_admin.php
   ```

5. **View logs**
   ```bash
   docker compose logs -f --tail 100
   ```

### Access the Platform

Open your browser and navigate to:
```
http://localhost:8084
```

Login with the admin credentials created in step 4.

## Services

The platform runs two Docker services:

- **iotafy_platform** - Main web interface (Apache + PHP)
- **iotafy_monitor** - Background device monitoring service

## Configuration

### Environment Variables

Edit `.env` to configure:

- `IOTAFY_APP_KEY` - Encryption key
- `SMTP_HOST`, `SMTP_PORT` - Email server settings
- `SMTP_USER`, `SMTP_PASS` - Email credentials
- `SMTP_FROM` - Sender email address

### SMTP Configuration (Optional)

For email notifications (used by monitoring service):

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=iotafy@yourdomain.com
SMTP_AUTH=on
SMTP_TLS=on
SMTP_STARTTLS=on
```

## Common Commands

```bash
# View logs
docker compose logs -f --tail 1000

# Restart services
docker compose restart

# Stop services
docker compose down

# Rebuild after code changes
docker compose down
docker compose build
docker compose up -d

# Access platform container shell
docker compose exec -it iotafy_platform bash

# Reset admin password
docker compose exec -it iotafy_platform php /var/www/html/reset_admin.php
```

## Data Persistence

Data is stored in the following directories (mounted as volumes):

- `data/` - SQLite database
- `logs/` - Application and monitoring logs
- `firmware/` - Firmware files

## Security Notes

⚠️ **Important:**
- Never commit `.env` to version control
- Change `IOTAFY_APP_KEY` only once during initial setup
- Changing the app key will invalidate existing 2FA secrets
- Use strong passwords for admin accounts
- Enable HTTPS in production environments

## Troubleshooting

### Container won't start
Check logs: `docker compose logs iotafy_platform`

### Missing IOTAFY_APP_KEY error
Ensure you've run step 2 of the installation process

### Database not initialized
The database is auto-created on first run. If issues persist:
```bash
docker compose exec iotafy_platform sqlite3 /var/www/html/data/device_info.db < /var/www/html/schema.sql
```

### Email not working
1. Verify SMTP settings in `.env`
2. Check msmtp logs: `docker compose exec iotafy_platform cat /var/www/html/logs/msmtp.log`
3. Test email: `docker compose exec iotafy_platform test-email.sh recipient@example.com`

## Development

### File Structure
```
IOTAfy/
├── data/              # SQLite database (auto-created)
├── logs/              # Application logs
├── firmware/          # Firmware files
├── .env               # Environment configuration
├── docker-compose.yml # Docker services definition
├── Dockerfile         # Container image
└── entrypoint.sh      # Container startup script
```

### Monitoring Service

The `iotafy_monitor` service runs `monitor_devices.php` every 60 seconds to:
- Check device status
- Send notifications
- Update device states

Monitor logs: `docker compose logs -f iotafy_monitor`

## License



## Support

For issues and questions, please open an issue on GitHub:
https://github.com/TelSiP-RLab/IOTAfy/issues
