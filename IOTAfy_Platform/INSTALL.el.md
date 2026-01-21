# IOTAfy Devices Management Platform — Οδηγίες Εγκατάστασης

## Περιεχόμενα

1. [Προαπαιτούμενα](#1-προαπαιτούμενα)
2. [Λήψη/Τοποθέτηση αρχείων](#2-λήψητοποθέτηση-αρχείων)
3. [Ρυθμίσεις PHP](#3-ρυθμίσεις-php)
4. [Δημιουργία/Αρχικοποίηση Βάσης Δεδομένων](#4-δημιουργίααρχικοποίηση-βάσης-δεδομένων-sqlite)
5. [Δικαιώματα/Φάκελοι](#5-δικαιώματαφάκελοι-logs-firmware-database)
6. [Μεταβλητές Περιβάλλοντος](#6-μεταβλητές-περιβάλλοντος-iotafy_app_key)
7. [Ρυθμίσεις Web Server](#7-ρυθμίσεις-web-server)
8. [Ενεργοποίηση HTTPS & Headers Ασφαλείας](#8-ενεργοποίηση-https--headers-ασφαλείας)
9. [Αρχική Διαμόρφωση Εφαρμογής](#9-αρχική-διαμόρφωση-εφαρμογής)
10. [Endpoints Συσκευών](#10-endpoints-συσκευών)
11. [Backup & Συντήρηση](#11-backup--συντήρηση)
12. [Αναβάθμιση / Μεταφορά](#12-αναβάθμιση--μεταφορά)
13. [Αντιμετώπιση Προβλημάτων](#13-αντιμετώπιση-προβλημάτων)

---

## 1. Προαπαιτούμενα

- **PHP 8.0 ή νεότερο** με τα extensions:
  - `pdo_sqlite`
  - `openssl`
  - `curl`
  - `mbstring`
  - `json`
- **Web Server**: Apache ή Nginx (Linux) / IIS ή Apache (Windows)
- Δυνατότητα εκτέλεσης PHP μέσω PHP-FPM ή mod_php (Apache), ή FastCGI (IIS)
- **SQLite** (ενσωματωμένο). Προαιρετικά το εργαλείο γραμμής εντολών `sqlite3` για γρήγορα dumps
- Δίκτυα/Firewall που επιτρέπουν πρόσβαση στον web server και, εφόσον χρειάζεται, από server προς συσκευές

### Έλεγχος PHP extensions (Linux)

```bash
php -m | grep -E "pdo_sqlite|openssl|curl|mbstring|json"
```

---

## 2. Λήψη/Τοποθέτηση αρχείων

Αντέγραψε όλα τα αρχεία του project στον web root, π.χ.:

- **Linux**: `/var/www/devices`
- **Windows (IIS)**: `C:\inetpub\wwwroot\devices`
- **Windows (Apache XAMPP)**: `C:\xampp\htdocs\devices`

---

## 3. Ρυθμίσεις PHP

Συνίσταται οι ακόλουθες ρυθμίσεις στο `php.ini` (προσαρμόστε αναλόγως):

```ini
session.cookie_samesite = Lax  # ή Strict εάν δεν απαιτούνται cross-site ροές
session.cookie_httponly = On
session.cookie_secure = On  # σε παραγωγή με HTTPS
upload_max_filesize = 16M  # ή μεγαλύτερο σύμφωνα με μέγεθος firmware
post_max_size = 32M  # πάντα ≥ upload_max_filesize
expose_php = Off
```

---

## 4. Δημιουργία/Αρχικοποίηση Βάσης Δεδομένων (SQLite)

Το αρχείο της βάσης είναι το `device_info.db` στη ρίζα του project. Αν δεν υπάρχει, δημιουργήστε το από το `schema.sql`.

### Linux

```bash
cd /var/www/devices
sqlite3 device_info.db < schema.sql
```

### Windows (PowerShell, με sqlite3.exe στο PATH)

```powershell
cd C:\inetpub\wwwroot\devices
sqlite3 device_info.db ".read schema.sql"
```

**Σημείωση**: Το application εκτελεί lazy-migration για στήλες 2FA όπου χρειάζεται.

---

## 5. Δικαιώματα/Φάκελοι (logs, firmware, database)

Δημιούργησε/Εξασφάλισε ύπαρξη φακέλων: `logs/`, `firmware/`

Ο web server πρέπει να έχει δυνατότητα εγγραφής στα: `logs/`, `firmware/` και στο αρχείο `device_info.db` (ή στον φάκελο του για να το δημιουργήσει αν λείπει).

### Linux (Apache/Nginx με χρήστη www-data)

```bash
sudo chown -R www-data:www-data /var/www/devices
sudo chmod -R 750 /var/www/devices
sudo mkdir -p /var/www/devices/logs /var/www/devices/firmware
sudo chmod 770 /var/www/devices/logs /var/www/devices/firmware
```

### Windows

Δώσε **Modify/Write** δικαιώματα στον Application Pool user (IIS) ή στον χρήστη υπηρεσίας του Apache για τους φακέλους `logs/`, `firmware/` και για το `device_info.db`.

---

## 6. Μεταβλητές Περιβάλλοντος (IOTAFY_APP_KEY)

Η εφαρμογή κρυπτογραφεί ευαίσθητα δεδομένα (π.χ. 2FA secret) με AES-256-GCM.

Ορίστε τη μεταβλητή περιβάλλοντος `IOTAFY_APP_KEY` με ασφαλή τιμή (32 bytes). Μπορεί να είναι raw ή base64 (με πρόθεμα `base64:`).

### Linux (bash)

```bash
export IOTAFY_APP_KEY="base64:$(openssl rand -base64 32)"
# Προσθέστε το και στο /etc/environment ή στο service unit ώστε να επιμένει μετά από reboot
```

### Windows (PowerShell)

```powershell
# Δημιουργία base64-κλειδιού 32 bytes
$bytes = 1..32 | ForEach-Object { Get-Random -Max 256 }
$env:IOTAFY_APP_KEY = "base64:" + [Convert]::ToBase64String([byte[]]$bytes)
# Ορίστε το ως System/User Environment Variable από GUI ή με setx για μόνιμη ρύθμιση
```

### Επιβεβαίωση στην εφαρμογή

Μετά το set, κάντε restart τον web server ώστε η μεταβλητή να είναι διαθέσιμη στο PHP-FPM/worker.

---

## 7. Ρυθμίσεις Web Server

### Apache (virtual host παράδειγμα)

```apache
<VirtualHost *:80>
    ServerName your-domain.example
    DocumentRoot /var/www/devices

    <Directory /var/www/devices>
        AllowOverride All
        Require all granted
        Options -Indexes
    </Directory>

    # Προαιρετικά: redirect σε HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]
</VirtualHost>
```

### Nginx (server block παράδειγμα)

```nginx
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
        fastcgi_pass unix:/run/php/php8.2-fpm.sock; # προσαρμόστε τη διαδρομή
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_read_timeout 300;
    }

    # Προαιρετικό redirect σε HTTPS
    return 301 https://$host$request_uri;
}
```

### IIS

- Προσθέστε site/virtual directory προς τον φάκελο του project
- Ενεργοποιήστε PHP μέσω FastCGI
- Ρυθμίστε URL Rewrite για redirect σε HTTPS εφόσον υπάρχει SSL site

---

## 8. Ενεργοποίηση HTTPS & Headers Ασφαλείας

- Ενεργοποιήστε TLS (Let's Encrypt ή εταιρικό πιστοποιητικό)
- Συνίσταται HSTS (Strict-Transport-Security)
- Προσθέστε security headers από web server:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - **Content-Security-Policy (CSP)**: ρυθμίστε whitelists για τα χρησιμοποιούμενα CDNs (Bootstrap, FontAwesome, jQuery, Chart.js)

### Παράδειγμα CSP (ελάχιστο, προσαρμόστε)

```
Content-Security-Policy: default-src 'self'; img-src 'self' data: https://chart.googleapis.com https://api.qrserver.com; script-src 'self' https://code.jquery.com https://stackpath.bootstrapcdn.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; connect-src 'self'; frame-ancestors 'none';
```

---

## 9. Αρχική Διαμόρφωση Εφαρμογής

### Δημιουργία admin χρήστη

Το `reset_admin.php` είναι ένα CLI-only script που δημιουργεί/επαναφέρει τον admin χρήστη με default credentials.

**Σημαντικό**: Το script μπορεί να εκτελεστεί **ΜΟΝΟ από command line (CLI)** και όχι από web browser για λόγους ασφαλείας.

#### Linux

```bash
cd /var/www/devices
php reset_admin.php
```

#### Windows (PowerShell)

```powershell
cd C:\inetpub\wwwroot\devices
php reset_admin.php
```

Το script θα:
- Δημιουργήσει/επαναφέρει τον admin χρήστη με:
  - **Username**: `admin`
  - **Password**: `admin`
  - **Role**: `admin`
  - **2FA**: Απενεργοποιημένο
- Καταγράψει την εκτέλεση στο log file

**Σημαντικό**: Μετά την πρώτη σύνδεση, **αλλάξτε αμέσως το password** από το admin panel για ασφάλεια.

**Εναλλακτικά**: Εισάγετε admin εγγραφή στον πίνακα `users` μέσω SQLite GUI/CLI. Ο κωδικός πρέπει να είναι `password_hash()` (δημιουργήστε με ένα μικρό PHP snippet ή μέσω εφαρμογής αλλαγής κωδικού)

### Πρώτα βήματα

1. Σύνδεση στο `login.php`
2. Προαιρετικά ενεργοποιήστε 2FA από τη σελίδα `profile.php` (απαιτεί `IOTAFY_APP_KEY`)
3. Δημιουργήστε χρήστες, ομάδες, αναθέστε συσκευές
4. Προσαρμόστε `EMAIL_FROM`/`EMAIL_SUBJECT` στο `config.inc` (αν θα στέλνετε emails)

---

## 10. Endpoints Συσκευών

- Τα endpoints π.χ. `server.php`, `ping.php`, απαιτούν έλεγχο με authkey του χρήστη
- Βεβαιωθείτε ότι κάθε συσκευή γνωρίζει το authkey (`profile.php` → Regenerate Authkey για τον χρήστη όπου ανήκει η συσκευή)
- Για κάθε κλήση, η εφαρμογή ελέγχει: `SELECT id FROM users WHERE authkey = :authkey`
- Συνίσταται χρήση HTTPS και περιορισμός firewall όπου είναι δυνατόν

---

## 11. Backup & Συντήρηση

### SQLite backup (Linux)

Χρησιμοποιήστε το `backup.sh` ή δημιουργήστε δικό σας cron job.

**Παράδειγμα cron** (κάθε βράδυ 03:30):

```bash
30 3 * * * cd /var/www/devices && ./backup.sh >> logs/server.log 2>&1
```

### Monitoring συσκευών (Linux)

Για να παρακολουθείτε αυτόματα την κατάσταση των συσκευών, προσθέστε ένα cron job που τρέχει το `monitor_devices.php` τακτικά (π.χ. κάθε λεπτό).

**Παράδειγμα cron** (κάθε λεπτό):

```bash
*/1 * * * * echo "\n==== $(date '+\%Y-\%m-\%d \%H:\%M:\%S') ====" >> /path/to/devices/logs/monitor.log && /usr/bin/php /path/to/devices/monitor_devices.php >> /path/to/devices/logs/monitor.log 2>&1
```

**Συγκεκριμένο παράδειγμα** (προσαρμόστε τις διαδρομές):

```bash
*/1 * * * * echo "\n==== $(date '+\%Y-\%m-\%d \%H:\%M:\%S') ====" >> /home/protontech/web/icp.protontech.gr/public_html/devices/logs/monitor.log && /usr/bin/php /home/protontech/web/icp.protontech.gr/public_html/devices/monitor_devices.php >> /home/protontech/web/icp.protontech.gr/public_html/devices/logs/monitor.log 2>&1
```

**Σημείωση**: Αντικαταστήστε `/path/to/devices` με την πραγματική διαδρομή του project σας και `/usr/bin/php` με τη διαδρομή του PHP executable (εύρεση με `which php`).

### Monitoring συσκευών (Windows)

Για να παρακολουθείτε αυτόματα την κατάσταση των συσκευών στο Windows, χρησιμοποιήστε το Task Scheduler.

**Μέθοδος 1: PowerShell Script + Task Scheduler**

1. Δημιουργήστε ένα PowerShell script `monitor_devices.ps1`:

```powershell
# monitor_devices.ps1
$logFile = "C:\inetpub\wwwroot\devices\logs\monitor.log"
$phpPath = "C:\php\php.exe"  # Προσαρμόστε τη διαδρομή του PHP
$scriptPath = "C:\inetpub\wwwroot\devices\monitor_devices.php"  # Προσαρμόστε τη διαδρομή

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path $logFile -Value "`n==== $timestamp ===="
& $phpPath $scriptPath | Add-Content -Path $logFile
```

2. Δημιουργήστε Scheduled Task:
   - Ανοίξτε το **Task Scheduler**
   - Κάντε κλικ **Create Basic Task**
   - Όνομα: "Monitor Devices"
   - Trigger: **Daily** → Επιλέξτε **Repeat task every: 1 minute** για 24 ώρες
   - Action: **Start a program**
   - Program: `powershell.exe`
   - Arguments: `-ExecutionPolicy Bypass -File "C:\inetpub\wwwroot\devices\monitor_devices.ps1"`

**Μέθοδος 2: Απευθείας με Task Scheduler (χωρίς script)**

1. Δημιουργήστε Scheduled Task:
   - Program: `C:\php\php.exe` (προσαρμόστε τη διαδρομή)
   - Arguments: `C:\inetpub\wwwroot\devices\monitor_devices.php >> C:\inetpub\wwwroot\devices\logs\monitor.log 2>&1`
   - Trigger: **Daily** → **Repeat task every: 1 minute** για 24 ώρες

**Σημείωση**: Στο Windows, για να τρέχει κάθε λεπτό, χρειάζεται να ορίσετε το trigger ως Daily με repetition κάθε 1 λεπτό. Εναλλακτικά, χρησιμοποιήστε το **schtasks** command line:

```powershell
schtasks /create /tn "Monitor Devices" /tr "C:\php\php.exe C:\inetpub\wwwroot\devices\monitor_devices.php >> C:\inetpub\wwwroot\devices\logs\monitor.log 2>&1" /sc minute /mo 1 /f
```

### Windows

Χρησιμοποιήστε Task Scheduler με PowerShell script που τρέχει `sqlite3 ".dump"` και κρατά αρχεία με timestamp.

### Logs

Παρακολουθήστε `logs/server.log` και `logs/monitor.log`. Η εφαρμογή κάνει rotation (ημερήσιο/βάσει μεγέθους).

---

## 12. Αναβάθμιση / Μεταφορά

1. Πάρτε backup του `device_info.db` και των φακέλων `firmware/` και `logs/`
2. Αντιγράψτε νέα αρχεία του app στο target
3. Ελέγξτε permissions, `IOTAFY_APP_KEY` και PHP extensions
4. Ελέγξτε ότι οι SQL αλλαγές (αν υπάρχουν) εφαρμόστηκαν. Η εφαρμογή κάνει lazy-check για 2FA στήλες, αλλά αν προστεθούν νέα αντικείμενα, τρέξτε το νέο schema/migrations
5. Κάντε smoke test: login, dashboard, device_management, upload/restore firmware, monitor_status

---

## 13. Αντιμετώπιση Προβλημάτων

### Σφάλματα login

- Ελέγξτε ότι υπάρχει ο χρήστης και ότι ο κωδικός είναι σωστά hashed
- Δείτε τις εγγραφές στο `login_attempts` για lockout. Περιμένετε ή κάντε admin unlock
- Αν έχετε ενεργό 2FA, βεβαιωθείτε ότι έχει οριστεί σωστά το `IOTAFY_APP_KEY` και ότι η ώρα συστήματος είναι συγχρονισμένη (NTP)

### Σφάλματα κρυπτογράφησης

- Ελέγξτε ότι η μεταβλητή περιβάλλοντος `IOTAFY_APP_KEY` είναι ορισμένη και ο web server έχει γίνει restart μετά τη ρύθμιση

### Upload firmware αποτυγχάνει

- Ελέγξτε permissions στον φάκελο `firmware/`
- Αυξήστε `upload_max_filesize` και `post_max_size` στο `php.ini`

### Εντολές restart σε συσκευή

- Ελέγξτε δικτυακή προσβασιμότητα/ports και credentials
- Αποφύγετε `SSL_VERIFYPEER=false` σε παραγωγή και προτιμήστε έγκυρα πιστοποιητικά

### 404/500 σφάλματα

- Ελέγξτε error logs web server και `logs/server.log`

---

## Σημειώσεις Ασφαλείας

- **Χρησιμοποιήστε πάντα HTTPS**
- Ενεργοποιήστε HSTS και security headers
- Περιορίστε πρόσβαση στα admin URLs μέσω firewall/VPN αν είναι εφικτό
- Κρατήστε τα κλειδιά και τα backups εκτός του web root και με περιορισμένα δικαιώματα