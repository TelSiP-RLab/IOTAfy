# Βιβλιοθήκες ESP32-dev, ESP32-S3, ESP32-C3, ESP32-C6 Project

Αυτό το αρχείο περιλαμβάνει όλες τις βιβλιοθήκες που χρησιμοποιούνται στο ESP32-S3 project.

## ESP32 Core Libraries (Arduino Framework)

### WiFi & Networking
- **WiFi.h** - Διαχείριση WiFi συνδέσεων
- **HTTPClient.h** - HTTP client για HTTP requests
- **HTTPUpdate.h** - Over-The-Air (OTA) firmware updates
- **WiFiClientSecure.h** - Ασφαλείς HTTPS συνδέσεις με SSL/TLS
- **WebServer.h** - Web server για HTTP requests και web interface

### Storage
- **Preferences.h** - Non-volatile storage (NVS) για αποθήκευση ρυθμίσεων
- **EEPROM.h** - EEPROM storage για μόνιμη αποθήκευση δεδομένων

## ESP-IDF Libraries

### System & OTA
- **esp_ota_ops.h** - OTA operations για firmware updates
- **esp_sleep.h** - Deep sleep functionality για εξοικονόμηση ενέργειας

### Hardware Drivers
- **driver/rtc_cntl.h** - Real-Time Clock (RTC) control
- **driver/gpio.h** - General Purpose Input/Output (GPIO) control

## Standard C/C++ Libraries

- **time.h** - Time functions για NTP sync και time management
- **Arduino.h** - Arduino core library (βασική βιβλιοθήκη)

## Custom Headers

- **esp32_board_config.h** - Προσαρμοσμένη διαμόρφωση για διαφορετικούς τύπους ESP32 boards

## Χρήση Βιβλιοθηκών

### WiFi & Networking
```cpp
#include <WiFi.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
```

### Storage
```cpp
#include <Preferences.h>
#include <EEPROM.h>
```

### ESP-IDF
```cpp
#include <esp_ota_ops.h>
#include <esp_sleep.h>
#include <driver/rtc_cntl.h>
#include <driver/gpio.h>
```

### Standard Libraries
```cpp
#include <time.h>
#include <Arduino.h>
```

## Σημειώσεις

- Οι βιβλιοθήκες είναι διαθέσιμες μέσω του Arduino Framework για ESP32
- Οι ESP-IDF libraries είναι μέρος του ESP-IDF framework
- Οι standard C libraries είναι διαθέσιμες από το toolchain

## Εκδόσεις

Αυτές οι βιβλιοθήκες είναι μέρος του:
- **Arduino ESP32 Core** (για τις Arduino-style libraries)
- **ESP-IDF** (για τις ESP-IDF libraries)
- **Standard C/C++ Toolchain** (για τις standard libraries)

---
