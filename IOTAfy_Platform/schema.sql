CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL
, email TEXT, full_name TEXT, 'authkey' TEXT, create_date DATETIME, created_by INTEGER, last_password_change DATETIME, failed_logins INTEGER DEFAULT 0, lock_time DATETIME NULL, admin_locked BOOLEAN DEFAULT 0, token, chat_id, notification_preference TEXT DEFAULT 'email', last_login DATETIME DEFAULT NULL, is_active INTEGER DEFAULT 1, max_failed_logins INTEGER DEFAULT 5, lockout_duration INTEGER DEFAULT 30, failed_login_attempts INTEGER DEFAULT 0, last_failed_login DATETIME, locked_until DATETIME, twofa_enabled INTEGER DEFAULT 0, twofa_secret TEXT);
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE group_permissions (
    group_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);
CREATE TABLE user_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL, assigned_date DATETIME DEFAULT '2024-01-01 00:00:00',
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);
CREATE TABLE device_groups (
        device_id INTEGER NOT NULL,
        group_id INTEGER NOT NULL, assigned_date DATETIME DEFAULT '2024-01-01 00:00:00',
        PRIMARY KEY (device_id, group_id),
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
        FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
    );
CREATE TABLE IF NOT EXISTS 'devices' (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            device_id TEXT NOT NULL,
            firmware_version TEXT NOT NULL,
            last_ping DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'offline'
        , timestamp DATETIME, external_ip TEXT, 'user_id'  INTEGER );
CREATE TABLE IF NOT EXISTS 'groups' (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL
, created_by INTEGER DEFAULT NULL, create_date DATETIME DEFAULT '2024-01-01 00:00:00');
CREATE TRIGGER delete_user_groups AFTER DELETE ON users
FOR EACH ROW
BEGIN
    DELETE FROM user_groups WHERE user_id = OLD.id;
END;
CREATE TRIGGER update_last_password_change AFTER UPDATE OF password ON users
FOR EACH ROW
BEGIN
    UPDATE users SET last_password_change = CURRENT_TIMESTAMP WHERE id = OLD.id;
END;
CREATE TRIGGER delete_device_groups AFTER DELETE ON devices
FOR EACH ROW
BEGIN
    DELETE FROM device_groups WHERE device_id = OLD.id;
END;
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    additional_info TEXT
);
