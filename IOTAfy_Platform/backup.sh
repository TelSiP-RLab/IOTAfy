#!/bin/bash

# Get the current date
CURRENT_DATE=$(date +'%Y-%m-%d_%H:%M')

# Paths
DB_PATH="/home/protontech/web/icp.protontech.gr/public_html/devices/device_info.db"
BACKUP_DIR="/home/protontech/backup"
DB_BACKUP_PATH="$BACKUP_DIR/device_info_backup_$CURRENT_DATE.sql"
SCHEMA_BACKUP_PATH="$BACKUP_DIR/device_info_schema_backup_$CURRENT_DATE.sql"
PROJECT_PATH="/home/protontech/web/icp.protontech.gr/public_html/devices"
PROJECT_BACKUP_PATH="$BACKUP_DIR/project_backup_$CURRENT_DATE.tar.gz"

# Backup database
if sqlite3 $DB_PATH .dump > $DB_BACKUP_PATH; then
    echo "Database backup created at $DB_BACKUP_PATH"
else
    echo "Failed to create database backup" >&2
fi

# Backup database schema
if sqlite3 $DB_PATH .schema > $SCHEMA_BACKUP_PATH; then
    echo "Database schema backup created at $SCHEMA_BACKUP_PATH"
else
    echo "Failed to create database schema backup" >&2
fi

# Archive project files
if tar -czvf $PROJECT_BACKUP_PATH $PROJECT_PATH; then
    echo "Project files backup created at $PROJECT_BACKUP_PATH"
else
    echo "Failed to create project files backup" >&2
fi

# Keep only the last 10 backups
cd $BACKUP_DIR || exit

# Remove old database backups
ls -t device_info_backup_*.sql | sed -e '1,10d' | xargs -d '\n' rm -f
ls -t device_info_schema_backup_*.sql | sed -e '1,10d' | xargs -d '\n' rm -f

# Remove old project backups
ls -t project_backup_*.tar.gz | sed -e '1,10d' | xargs -d '\n' rm -f

