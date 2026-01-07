#include "icp_esp32.h"
// Simple RAM ring buffer for web logs
static const size_t WEB_LOG_BUFFER_CAPACITY = 4096; // 4KB ring buffer
static char webLogBuffer[WEB_LOG_BUFFER_CAPACITY];
static size_t webLogHead = 0;
static bool webLogWrapped = false;

// Basic HTML escape helper
String ICP_ESP32::htmlEscape(const String &in) {
    String out;
    out.reserve(in.length());
    for (size_t i = 0; i < in.length(); ++i) {
        char c = in[i];
        switch (c) {
            case '&': out += F("&amp;"); break;
            case '<': out += F("&lt;"); break;
            case '>': out += F("&gt;"); break;
            case '"': out += F("&quot;"); break;
            case '\'': out += F("&#39;"); break;
            default: out += c; break;
        }
    }
    return out;
}


// Root CA Certificate
const char* rootCACertificate = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
)EOF";

ICP_ESP32::ICP_ESP32(int ledPin, int resetButtonPin, int fwVersion)
    : _ledPin(ledPin),
      _resetButtonPin(resetButtonPin),
      _fwVersion(fwVersion),
      _boardType(ESP32BoardConfig::detectBoardType()),
      PERIOD(60000UL),
      wifiConnectTimeout(30000),
      AP_MODE_DURATION(600000UL),
      DEEP_SLEEP_DURATION(600000000UL),
      fwUrlBase("https://icp.protontech.gr/devices/firmware/"),
      postUrl("https://icp.protontech.gr/devices/server.php"),
      pingUrl("https://icp.protontech.gr/devices/ping.php"),
      authUrl("https://icp.protontech.gr/devices/auth.php"),
      http_username("admin") {
    
    serverPort = 80;
    server = nullptr;
    target_time = 0L;
    ping_interval = 900000UL;
    last_ping_time = 0L;
    bootTime = 0;
    buttonPressStartTime = 0;
    wifiConnectStartTime = 0;
    last_reconnect_attempt = 0L;
    ap_mode_start_time = 0L;
    
    skipUpdateCheck = false;
    debugEnabled = true;
    webDebugEnabled = false;
    updateAvailable = false;
    isButtonPressed = false;
    wifiAttemptInProgress = false;
    wifiInitialized = false;
    in_ap_mode = false;
    
    reconnect_attempts = 0;
    MAX_RECONNECT_ATTEMPTS = 10;
    reconnect_attempt_interval = 5000;
    max_reconnect_attempt_interval = 60000;

    // Προσαρμογή των ρυθμίσεων με βάση τον τύπο της πλακέτας
    if (_boardType == ESP32BoardType::ESP32_C3) {
        // Το ESP32-C3 έχει μικρότερη μνήμη, προσαρμόζουμε τις ρυθμίσεις
        DEEP_SLEEP_DURATION = 300000000UL; // 5 λεπτά
        AP_MODE_DURATION = 300000UL; // 5 λεπτά
    }
}

ICP_ESP32::~ICP_ESP32() {
    if (server != nullptr) {
        server->close();
        delete server;
        server = nullptr;
    }
}

void ICP_ESP32::begin() {
    // Ειδική διαμόρφωση Serial για κάθε πλακέτα
    if (_boardType == ESP32BoardType::ESP32_S3) {
        // Για ESP32-S3 χρησιμοποιούμε μόνο USB CDC για το Serial
        // ΜΗΝ αρχικοποιούμε Serial0 για να αποφύγουμε συγκρούσεις
        Serial.begin(115200);  // USB CDC μόνο
        
        // Περιμένουμε περισσότερο χρόνο για το USB CDC να αρχικοποιηθεί
        unsigned long startTime = millis();
        while (!Serial && (millis() - startTime) < 5000) {  // Αύξηση timeout σε 5 δευτερόλεπτα
            delay(100);  // Αύξηση delay για καλύτερη σταθερότητα
        }
        
        // Επιβεβαίωση ότι το Serial είναι έτοιμο
        if (Serial) {
            Serial.println("\nUSB CDC initialized successfully");
            delay(100);  // Επιπλέον καθυστέρηση για σταθερότητα
        } else {
            // Fallback: χρήση Serial0 μόνο αν το USB CDC αποτύχει
            Serial0.begin(115200, SERIAL_8N1, 44, 43);
            Serial0.println("\nFallback to UART0 - USB CDC failed");
        }
    } else if (_boardType == ESP32BoardType::ESP32_C3 || _boardType == ESP32BoardType::ESP32_C6) {
        // Για ESP32-C3 και ESP32-C6 χρησιμοποιούμε USB CDC
        Serial.begin(115200);
        
        // Περιμένουμε μέχρι να είναι διαθέσιμο το USB CDC
        unsigned long startTime = millis();
        while (!Serial && (millis() - startTime) < 2000) {
            delay(50);
        }
        
        if (Serial) {
            Serial.println("\nUSB CDC initialized for " + String(ESP32BoardConfig::getBoardName()));
        }
    } else {
        Serial.begin(115200);  // Κανονικό UART για ESP32
    }
    
    delay(500);
    
    // Ειδική διαμόρφωση για ESP32-S3 USB CDC
    if (_boardType == ESP32BoardType::ESP32_S3) {
        // Περιμένουμε επιπλέον χρόνο για το USB CDC να σταθεροποιηθεί
        delay(1000);
        Serial.setDebugOutput(true);
        // Επιπλέον καθυστέρηση μετά το setDebugOutput
        delay(200);
    } else {
        Serial.setDebugOutput(true);
    }
    
    bootTime = millis();

    Serial.println();
    debugPrintln("Starting setup...");

    for (uint8_t t = 5; t > 0; t--) {
        debugPrintln("[SETUP] WAIT " + String(t) + "...");
        Serial.flush();
        delay(1000);
    }
    
    pinMode(_ledPin, OUTPUT);
    digitalWrite(_ledPin, HIGH);
    pinMode(_resetButtonPin, INPUT_PULLUP);
    
    EEPROM.begin(EEPROM_SIZE);
    
    unsigned long saved_ap_duration;
    unsigned long saved_deep_sleep_duration;
    unsigned int saved_reconnect_attempts;
    unsigned long saved_reconnect_interval;
    unsigned long saved_max_reconnect_interval;
    
    EEPROM.get(AP_DURATION_ADDR, saved_ap_duration);
    EEPROM.get(DEEP_SLEEP_DURATION_ADDR, saved_deep_sleep_duration);
    EEPROM.get(RECONNECT_ATTEMPTS_ADDR, saved_reconnect_attempts);
    EEPROM.get(RECONNECT_INTERVAL_ADDR, saved_reconnect_interval);
    EEPROM.get(MAX_RECONNECT_INTERVAL_ADDR, saved_max_reconnect_interval);
    
    if (saved_ap_duration != 0) {
        AP_MODE_DURATION = saved_ap_duration;
        debugPrintln("Updated AP Mode Duration: " + String(AP_MODE_DURATION / 60000) + " minutes");
    }
    
    if (saved_deep_sleep_duration != 0) {
        DEEP_SLEEP_DURATION = saved_deep_sleep_duration;
        debugPrintln("Updated Deep Sleep Duration: " + String(DEEP_SLEEP_DURATION / 60000000) + " minutes");
    }
    
    if (saved_reconnect_attempts != 0) {
        MAX_RECONNECT_ATTEMPTS = saved_reconnect_attempts;
        debugPrintln("Updated Max Reconnect Attempts: " + String(MAX_RECONNECT_ATTEMPTS));
    }
    
    if (saved_reconnect_interval != 0) {
        reconnect_attempt_interval = saved_reconnect_interval;
        debugPrintln("Updated Reconnect Interval: " + String(reconnect_attempt_interval) + " ms");
    }
    
    if (saved_max_reconnect_interval != 0) {
        max_reconnect_attempt_interval = saved_max_reconnect_interval;
        debugPrintln("Updated Max Reconnect Interval: " + String(max_reconnect_attempt_interval) + " ms");
    }

    preferences.begin("credentials", false);
    
    size_t totalBytes = preferences.freeEntries() * 32;
    debugPrintln("Available storage space: " + String(totalBytes) + " bytes");
    
    bool ota_failed = preferences.getBool("ota_failed", false);
    if (ota_failed) {
        debugPrintln("Detected failed firmware installation. Skipping update check.");
        skipUpdateCheck = true;
        preferences.putBool("skipUpdateCheck", true);
    } else {
        skipUpdateCheck = preferences.getBool("skipUpdateCheck", false);
    }
    
    serverPort = preferences.getInt("serverPort", 80);
    if (server != nullptr) {
        server->close();
        delete server;
        server = nullptr;
    }
    server = new WebServer(serverPort);

    http_password = preferences.getString("web_password", "");
    authKey = preferences.getString("auth_key", "");
    debugEnabled = preferences.getBool("debugEnabled", true);
    webDebugEnabled = preferences.getBool("webDebugEnabled", false); // default: off

    bool isConfigured = preferences.getBool("isConfigured", false);

    if (!isConfigured) {
        startAPMode();
        return;
    }
    
    startWiFiConnection();
}

void ICP_ESP32::connectToWiFi() {
    WiFi.mode(WIFI_STA);
    WiFi.onEvent([this](WiFiEvent_t event, WiFiEventInfo_t info) {
        this->WiFiEvent(event, info);
    });
    String ssid = preferences.getString("ssid");
    String wifi_password = preferences.getString("wifi_password");
    debugPrintln("Attempting to connect to WiFi: " + ssid);
    WiFi.begin(ssid.c_str(), wifi_password.c_str());
    wifiConnectStartTime = millis();
    wifiAttemptInProgress = true;
}

void ICP_ESP32::startWiFiConnection() {
    connectToWiFi();
    wifiInitialized = false;
}

void ICP_ESP32::enterDeepSleepMode() {
    debugPrintln("Entering deep sleep mode for " + String(DEEP_SLEEP_DURATION / 60000000) + " minutes...");
    
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    
    if (server != nullptr) {
        server->close();
    }
    
    gpio_reset_pin(GPIO_NUM_0);
    
    esp_sleep_enable_timer_wakeup(DEEP_SLEEP_DURATION);
    
    debugPrintln("Entering deep sleep mode...");
    Serial.flush();
    delay(1000);
    esp_deep_sleep_start();
}

void ICP_ESP32::reconnectToWiFi() {
    if (WiFi.status() != WL_CONNECTED && 
        millis() - last_reconnect_attempt >= reconnect_attempt_interval && 
        !wifiAttemptInProgress && 
        reconnect_attempts < MAX_RECONNECT_ATTEMPTS) {
        
        reconnect_attempts++;
        debugPrintln("Attempting to reconnect to WiFi (Attempt #" + String(reconnect_attempts) + " of " + String(MAX_RECONNECT_ATTEMPTS) + ")...");
        connectToWiFi();
        last_reconnect_attempt = millis();
        reconnect_attempt_interval = min(reconnect_attempt_interval * 2, max_reconnect_attempt_interval);
        
        if (reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {
            if (in_ap_mode) {
                debugPrintln("Maximum reconnection attempts reached in AP mode. Switching to deep sleep mode...");
                enterDeepSleepMode();
            } else {
                debugPrintln("Maximum reconnection attempts reached. Switching to AP mode...");
                startAPMode();
            }
        }
    }
}

void ICP_ESP32::WiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
    switch (event) {
        case ARDUINO_EVENT_WIFI_STA_GOT_IP:
            debugPrintln("WiFi connected, IP: " + WiFi.localIP().toString());
            last_reconnect_attempt = millis();
            reconnect_attempt_interval = 5000;
            reconnect_attempts = 0;
            break;
        case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
            debugPrintln("WiFi disconnected. Attempting to reconnect...");
            break;
        default:
            break;
    }
}

void ICP_ESP32::debugPrint(String message) {
    if (debugEnabled) {
        Serial.print(message);
        // ΜΗΝ χρησιμοποιούμε Serial0 για ESP32-S3 για να αποφύγουμε συγκρούσεις
        // Το USB CDC είναι αρκετό για το ESP32-S3
    }
    if (webDebugEnabled) {
        String logMessage = getCurrentTime() + " - " + message;
        appendLog(logMessage);
    }
}

void ICP_ESP32::debugPrintln(String message) {
    if (debugEnabled) {
        Serial.println(message);
        // ΜΗΝ χρησιμοποιούμε Serial0 για ESP32-S3 για να αποφύγουμε συγκρούσεις
        // Το USB CDC είναι αρκετό για το ESP32-S3
    }
    if (webDebugEnabled) {
        String logMessage = getCurrentTime() + " - " + message + "\n";
        appendLog(logMessage);
    }
}

String ICP_ESP32::getMAC() {
    uint8_t mac[6];
    char macAddr[18];
    WiFi.macAddress(mac);
    sprintf(macAddr, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macAddr);
}

String ICP_ESP32::getIPAddress() {
    return WiFi.localIP().toString();
}

String ICP_ESP32::getExternalIPAddress() {
    HTTPClient http;
    http.begin("http://api.ipify.org");
    int httpResponseCode = http.GET();
    String externalIP = "";
    if (httpResponseCode == 200) {
        externalIP = http.getString();
    }
    http.end();
    return externalIP;
}

// RAM ring buffer logging helpers
void ICP_ESP32::appendLog(const String &message) {
    const char* data = message.c_str();
    size_t len = strlen(data);
    for (size_t i = 0; i < len; ++i) {
        webLogBuffer[webLogHead] = data[i];
        webLogHead = (webLogHead + 1) % WEB_LOG_BUFFER_CAPACITY;
        if (webLogHead == 0) {
            webLogWrapped = true;
        }
    }
}

String ICP_ESP32::getLogs() {
    if (!webLogWrapped && webLogHead == 0) {
        return String("No logs available");
    }
    String out;
    out.reserve(WEB_LOG_BUFFER_CAPACITY + 32);
    if (webLogWrapped) {
        for (size_t i = webLogHead; i < WEB_LOG_BUFFER_CAPACITY; ++i) {
            out += webLogBuffer[i];
        }
    }
    for (size_t i = 0; i < webLogHead; ++i) {
        out += webLogBuffer[i];
    }
    return out;
}

void ICP_ESP32::clearLogs() {
    webLogHead = 0;
    webLogWrapped = false;
}

// Basic JSON escape (for future use if needed)
String ICP_ESP32::jsonEscape(const String &in) {
    String out;
    out.reserve(in.length());
    for (size_t i = 0; i < in.length(); ++i) {
        char c = in[i];
        switch (c) {
            case '"': out += F("\\\""); break;
            case '\\': out += F("\\\\"); break;
            case '\b': out += F("\\b"); break;
            case '\f': out += F("\\f"); break;
            case '\n': out += F("\\n"); break;
            case '\r': out += F("\\r"); break;
            case '\t': out += F("\\t"); break;
            default:
                if ((uint8_t)c < 0x20) {
                    char buf[7];
                    sprintf(buf, "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

void ICP_ESP32::sendDeviceInfo() {
    if (authKey == nullptr || authKey.length() == 0) {
        debugPrintln("Error: Authorization key is not set. Aborting device info send.");
        return;
    }

    if (WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.begin(client, postUrl);

        String device_name = htmlEscape(preferences.getString("device_name", "My ESP32 Device"));

        String jsonPayload = "{\"ip\":\"" + getIPAddress() + "\",";
        jsonPayload += "\"external_ip\":\"" + getExternalIPAddress() + "\",";
        jsonPayload += "\"mac\":\"" + getMAC() + "\",";
        jsonPayload += "\"device_id\":\"" + String(ESP.getEfuseMac()) + "\",";
        jsonPayload += "\"name\":\"" + device_name + "\",";
        jsonPayload += "\"board_type\":\"" + String(ESP32BoardConfig::getBoardName()) + "\",";
        jsonPayload += "\"firmware_version\":\"" + String(_fwVersion) + "\"}";

        debugPrintln("Sending device info with payload: " + jsonPayload);

        http.addHeader("Content-Type", "application/json");
        http.addHeader("Authorization", authKey);

        int httpResponseCode = http.POST(jsonPayload);
        if (httpResponseCode > 0) {
            String response = http.getString();
            debugPrintln("HTTP Response code: " + String(httpResponseCode));
            debugPrintln("Response: " + response);
        } else {
            debugPrintln("Error on sending POST: " + String(httpResponseCode));
            debugPrintln("Error message: " + http.errorToString(httpResponseCode));
        }

        http.end();
    } else {
        debugPrintln("WiFi not connected");
    }
}

void ICP_ESP32::checkForUpdates() {
    if (authKey == nullptr || authKey.length() == 0) {
        debugPrintln("Error: Authentication key is not set.");
        return;
    }

    if (WiFi.status() != WL_CONNECTED) {
        debugPrintln("WiFi not connected. Cannot check for updates.");
        return;
    }

    // First validate the auth key
    HTTPClient authHttp;
    authHttp.begin(client, authUrl);
    String jsonPayload = "{\"auth_key\":\"" + authKey + "\"}";
    authHttp.addHeader("Content-Type", "application/json");
    authHttp.addHeader("Authorization", authKey);

    int authResponseCode = authHttp.POST(jsonPayload);
    String authResponse = authHttp.getString();
    debugPrintln("Server response: " + authResponse);
    authHttp.end();

    if (authResponseCode != 200 || 
        (authResponse.indexOf("\"status\":\"success\"") == -1 && 
         authResponse.indexOf("\"status\":\"approved\"") == -1 && 
         authResponse.indexOf("\"valid\":true") == -1 && 
         authResponse.indexOf("\"status\": \"success\"") == -1 && 
         authResponse.indexOf("\"status\": \"approved\"") == -1 && 
         authResponse.indexOf("\"valid\": true") == -1)) {
        debugPrintln("Invalid authentication key. Update check cancelled.");
        return;
    }

    updateAvailable = false;
    String mac = getMAC();
    String fwURL = String(fwUrlBase);
    fwURL.concat(mac);
    String fwVersionURL = fwURL;
    fwVersionURL.concat(".version");

    debugPrintln("Checking for new firmware updates...");

    HTTPClient http;
    http.begin(client, fwVersionURL);
    http.addHeader("Authorization", authKey);

    int httpCode = http.GET();
    if (httpCode == 200) {
        String newFWVersion = http.getString();

        debugPrint("Current firmware version: ");
        debugPrintln(String(_fwVersion));
        debugPrint("Available firmware version on server: ");
        debugPrintln(newFWVersion);

        int newVersion = newFWVersion.toInt();

        if (newVersion > _fwVersion) {
            debugPrintln("New firmware version available.");
            updateAvailable = true;
        } else {
            debugPrintln("You already have the latest version.");
        }
    } else if (httpCode == 401) {
        debugPrintln("Unauthorized access. Authentication key is not valid.");
    } else {
        debugPrint("Firmware version check failed, HTTP response code: ");
        debugPrintln(String(httpCode));
    }
    http.end();
}

void ICP_ESP32::checkForUpdatesAndUpdateIfNeeded() {
    if (skipUpdateCheck) {
        debugPrintln("Skipping update check due to failed firmware installation.");
        return;
    }

    // First validate the auth key
    HTTPClient authHttp;
    authHttp.begin(client, authUrl);
    String jsonPayload = "{\"auth_key\":\"" + authKey + "\"}";
    authHttp.addHeader("Content-Type", "application/json");
    authHttp.addHeader("Authorization", authKey);

    int authResponseCode = authHttp.POST(jsonPayload);
    String authResponse = authHttp.getString();
    debugPrintln("Server response: " + authResponse);
    authHttp.end();

    if (authResponseCode != 200 || 
        (authResponse.indexOf("\"status\":\"success\"") == -1 && 
         authResponse.indexOf("\"status\":\"approved\"") == -1 && 
         authResponse.indexOf("\"valid\":true") == -1 && 
         authResponse.indexOf("\"status\": \"success\"") == -1 && 
         authResponse.indexOf("\"status\": \"approved\"") == -1 && 
         authResponse.indexOf("\"valid\": true") == -1)) {
        debugPrintln("Invalid authentication key. Update check cancelled.");
        return;
    }

    if (WiFi.status() == WL_CONNECTED) {
        String mac = getMAC();
        String fwURL = String(fwUrlBase);
        fwURL.concat(mac);
        String fwVersionURL = fwURL;
        fwVersionURL.concat(".version");

        debugPrintln("Checking for new firmware updates...");

        HTTPClient http;
        http.begin(client, fwVersionURL);
        http.addHeader("Authorization", authKey);

        int httpCode = http.GET();
        if (httpCode == 200) {
            String newFWVersion = http.getString();

            debugPrint("Current firmware version: ");
            debugPrintln(String(_fwVersion));
            debugPrint("Available firmware version on server: ");
            debugPrintln(newFWVersion);

            int newVersion = newFWVersion.toInt();

            if (newVersion > _fwVersion) {
                debugPrintln("New firmware version available. Installing...");
                installUpdate();
            } else {
                debugPrintln("You already have the latest version.");
            }
        } else if (httpCode == 401) {
            debugPrintln("Unauthorized access. Authentication key is not valid.");
        } else {
            debugPrint("Firmware version check failed, HTTP response code: ");
            debugPrintln(String(httpCode));
        }
        http.end();
    }
}

void ICP_ESP32::installUpdate() {
    if (authKey == nullptr || authKey.length() == 0) {
        debugPrintln("Error: Authentication key is not set.");
        return;
    }

    if (WiFi.status() != WL_CONNECTED) {
        debugPrintln("WiFi not connected. Cannot install update.");
        return;
    }

    if (skipUpdateCheck) {
        debugPrintln("Skipping firmware installation due to failed installation.");
        return;
    }

    // First validate the auth key
    HTTPClient authHttp;
    authHttp.begin(client, authUrl);
    String jsonPayload = "{\"auth_key\":\"" + authKey + "\"}";
    authHttp.addHeader("Content-Type", "application/json");
    authHttp.addHeader("Authorization", authKey);

    int authResponseCode = authHttp.POST(jsonPayload);
    String authResponse = authHttp.getString();
    debugPrintln("Server response: " + authResponse);
    authHttp.end();

    if (authResponseCode != 200 || 
        (authResponse.indexOf("\"status\":\"success\"") == -1 && 
         authResponse.indexOf("\"status\":\"approved\"") == -1 && 
         authResponse.indexOf("\"valid\":true") == -1 && 
         authResponse.indexOf("\"status\": \"success\"") == -1 && 
         authResponse.indexOf("\"status\": \"approved\"") == -1 && 
         authResponse.indexOf("\"valid\": true") == -1)) {
        debugPrintln("Invalid authentication key. Update installation cancelled.");
        return;
    }

    String mac = getMAC();
    String fwURL = String(fwUrlBase);
    fwURL.concat(mac);
    String fwVersionURL = fwURL;
    fwVersionURL.concat(".version");

    debugPrintln("Updating and installing new firmware...");

    HTTPClient http;
    http.begin(client, fwVersionURL);
    http.addHeader("Authorization", authKey);

    int httpCode = http.GET();
    if (httpCode == 200) {
        String newFWVersion = http.getString();

        debugPrint("Current firmware version: ");
        debugPrintln(String(_fwVersion));
        debugPrint("Available firmware version on server: ");
        debugPrintln(newFWVersion);

        int newVersion = newFWVersion.toInt();

        if (newVersion > _fwVersion) {
            debugPrintln("Preparing to update the device...");
            String fwImageURL = fwURL;
            fwImageURL.concat(".bin");

            const esp_partition_t* update_partition = esp_ota_get_next_update_partition(NULL);
            if (update_partition == NULL) {
                debugPrintln("No OTA partition available.");
                return;
            }

            debugPrintln("Checking partition size...");
            HTTPClient httpCheckSize;
            httpCheckSize.begin(client, fwImageURL);
            httpCheckSize.addHeader("Authorization", authKey);
            int httpCheckSizeCode = httpCheckSize.GET();
            if (httpCheckSizeCode != 200) {
                debugPrintln("Failed to get firmware size.");
                return;
            }
            int contentLength = httpCheckSize.getSize();
            httpCheckSize.end();

            if (contentLength <= 0 || contentLength > update_partition->size) {
                debugPrintln("Not enough space for the new firmware.");
                return;
            }

            debugPrintln("Sufficient space available. Proceeding with the update...");
            digitalWrite(_ledPin, LOW);

            HTTPUpdateResult ret = httpUpdate.update(client, fwImageURL);

            switch (ret) {
                case HTTP_UPDATE_FAILED:
                    debugPrint("HTTP_UPDATE_FAILED Error (");
                    debugPrint(String(httpUpdate.getLastError()));
                    debugPrint("): ");
                    debugPrintln(httpUpdate.getLastErrorString());
                    preferences.putBool("ota_failed", true);
                    esp_ota_mark_app_invalid_rollback_and_reboot();
                    break;

                case HTTP_UPDATE_NO_UPDATES:
                    debugPrintln("HTTP_UPDATE_NO_UPDATES");
                    break;

                case HTTP_UPDATE_OK:
                    debugPrintln("HTTP_UPDATE_OK");
                    preferences.putBool("ota_failed", false);
                    esp_ota_mark_app_valid_cancel_rollback();
                    break;
            }
            digitalWrite(_ledPin, HIGH);
        } else {
            debugPrintln("You already have the latest version.");
            digitalWrite(_ledPin, HIGH);
        }
    } else if (httpCode == 401) {
        debugPrintln("Unauthorized access. Authentication key is not valid.");
    } else {
        debugPrint("Firmware version check failed, HTTP response code: ");
        debugPrintln(String(httpCode));
    }
    http.end();
}

void ICP_ESP32::sendPing() {
    if (authKey == nullptr || authKey.length() == 0) {
        debugPrintln("Error: Authorization key is not set. Aborting device info send.");
        return;
    }

    if (WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.begin(client, pingUrl);

        String jsonPayload = "{\"device_id\":\"" + String(ESP.getEfuseMac()) + "\",";
        jsonPayload += "\"mac\":\"" + getMAC() + "\",";
        jsonPayload += "\"status\":\"online\"}";

        debugPrintln("Sending Ping with payload: " + jsonPayload);

        http.addHeader("Content-Type", "application/json");
        http.addHeader("Authorization", authKey);

        int httpResponseCode = http.POST(jsonPayload);
        if (httpResponseCode > 0) {
            String response = http.getString();
            debugPrintln("Ping HTTP Response code: " + String(httpResponseCode));
            debugPrintln("Response: " + response);
        } else {
            debugPrintln("Error on sending Ping POST: " + String(httpResponseCode));
            debugPrintln("Error message: " + http.errorToString(httpResponseCode));
        }

        http.end();
    } else {
        debugPrintln("WiFi not connected");
    }
}

void ICP_ESP32::rollbackToFirmware() {
    debugPrintln("Rolling back to previous firmware...");

    esp_ota_img_states_t ota_state;
    const esp_partition_t* partition = esp_ota_get_running_partition();

    if (partition != nullptr) {
        esp_err_t err = esp_ota_get_state_partition(partition, &ota_state);
        if (err == ESP_OK && ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            debugPrintln("OTA partition rollback");
            if (esp_ota_set_boot_partition(partition) == ESP_OK) {
                debugPrintln("Rollback successful! Restarting...");
                ESP.restart();
            } else {
                debugPrintln("Rollback failed!");
            }
        }
    }
}

void ICP_ESP32::startAPMode() {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ESP32_Config", "12345678");
    IPAddress IP = WiFi.softAPIP();
    debugPrintln("Access Point IP address: " + IP.toString());
    in_ap_mode = true;
    ap_mode_start_time = millis();

    server->on("/", HTTP_GET, [this]() {
        String html = "<html><head><title>ESP32 Configuration</title>";
        html += "<style>";
        html += "body { font-family: Arial, sans-serif; margin: 20px; }";
        html += ".container { max-width: 600px; margin: 0 auto; }";
        html += "h1 { color: #333; }";
        html += ".form-group { margin-bottom: 15px; }";
        html += "label { display: block; margin-bottom: 5px; }";
        html += "input[type='text'], input[type='password'] { width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; }";
        html += "button { background-color: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }";
        html += "button:hover { background-color: #45a049; }";
        html += "</style></head><body>";
        html += "<div class='container'>";
        html += "<h1>ESP32 Configuration</h1>";
        html += "<form action='/setup_wifi' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='ssid'>SSID:</label>";
        html += "<input type='text' id='ssid' name='ssid' required>";
        html += "</div>";
        html += "<div class='form-group'>";
        html += "<label for='password'>WiFi Password:</label>";
        html += "<input type='password' id='password' name='password' required>";
        html += "</div>";
        html += "<div class='form-group'>";
        html += "<label for='web_password'>Web Password:</label>";
        html += "<input type='password' id='web_password' name='web_password' required>";
        html += "</div>";
        html += "<div class='form-group'>";
        html += "<label for='auth_key'>Authentication Key:</label>";
        html += "<input type='text' id='auth_key' name='auth_key' value='" + authKey + "' required>";
        html += "</div>";
        html += "<button type='submit'>Save</button>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/setup_wifi", HTTP_POST, [this]() {
        String html = "<html><head><title>WiFi Setup</title>";
        html += "<style>";
        html += "body { font-family: Arial, sans-serif; margin: 20px; text-align: center; }";
        html += ".message { margin: 20px; padding: 20px; border-radius: 4px; }";
        html += ".success { background-color: #dff0d8; color: #3c763d; border: 1px solid #d6e9c6; }";
        html += ".error { background-color: #f2dede; color: #a94442; border: 1px solid #ebccd1; }";
        html += "</style></head><body>";

        if (server->hasArg("ssid") && server->hasArg("password") && server->hasArg("web_password") && server->hasArg("auth_key")) {
            String newSSID = server->arg("ssid");
            String newPassword = server->arg("password");
            String newWebPassword = server->arg("web_password");
            String newAuthKey = server->arg("auth_key");
            preferences.putString("ssid", newSSID);
            preferences.putString("wifi_password", newPassword);
            preferences.putString("web_password", newWebPassword);
            preferences.putString("auth_key", newAuthKey);
            preferences.putBool("isConfigured", true);
            WiFi.softAPdisconnect(true);
            WiFi.mode(WIFI_STA);
            WiFi.begin(newSSID.c_str(), newPassword.c_str());
            
            int timeout = 30;
            while (WiFi.status() != WL_CONNECTED && timeout > 0) {
                delay(1000);
                debugPrint(".");
                timeout--;
            }
            
            if (WiFi.status() == WL_CONNECTED) {
                html += "<div class='message success'>";
                html += "<h2>Connected Successfully</h2>";
                html += "<p>Connected to " + newSSID + "</p>";
                html += "<p>The device will restart now...</p>";
                html += "</div>";
                server->send(200, "text/html", html);
                delay(2000);
                ESP.restart();
            } else {
                html += "<div class='message error'>";
                html += "<h2>Connection Failed</h2>";
                html += "<p>Failed to connect to " + newSSID + "</p>";
                html += "<p><a href='/'>Go back and try again</a></p>";
                html += "</div>";
                server->send(200, "text/html", html);
            }
        } else {
            html += "<div class='message error'>";
            html += "<h2>Invalid Request</h2>";
            html += "<p>Please fill in all required fields</p>";
            html += "<p><a href='/'>Go back and try again</a></p>";
            html += "</div>";
            server->send(400, "text/html", html);
        }
        html += "</body></html>";
    });

    server->begin();
}

void ICP_ESP32::setClock() {
    configTime(3 * 3600, 0, "pool.ntp.org", "time.nist.gov");
    debugPrint("Waiting for NTP time sync: ");
    time_t now = time(nullptr);
    while (now < 8 * 3600 * 2) {
        delay(500);
        debugPrint(".");
        now = time(nullptr);
    }
    debugPrintln("");
    struct tm timeinfo;
    gmtime_r(&now, &timeinfo);
    debugPrint("Current time: ");
    debugPrintln(asctime(&timeinfo));
}

void ICP_ESP32::resetToDefault() {
    debugPrintln("Resetting to default configuration...");
    preferences.clear();
    ESP.restart();
}

void ICP_ESP32::initializeServer() {
    // Main Menu Endpoint
    server->on("/", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String device_name = preferences.getString("device_name", "My ESP32 Device");
        String html = "<html><head><title>Main Menu</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "<script src='https://code.jquery.com/jquery-3.5.1.slim.min.js'></script>";
        html += "<script src='https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js'></script>";
        html += "<script src='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js'></script>";
        html += "</head><body>";
        html += "<nav class='navbar navbar-expand-lg navbar-light bg-light'>";
        html += "<a class='navbar-brand' href='#'>IOTAfy ESP32 Device</a>";
        html += "<button class='navbar-toggler' type='button' data-toggle='collapse' data-target='#navbarNav' aria-controls='navbarNav' aria-expanded='false' aria-label='Toggle navigation'>";
        html += "<span class='navbar-toggler-icon'></span>";
        html += "</button>";
        html += "<div class='collapse navbar-collapse' id='navbarNav'>";
        html += "<ul class='navbar-nav'>";
        html += "<li class='nav-item dropdown'>";
        html += "<a class='nav-link dropdown-toggle' href='#' id='updatesDropdown' role='button' data-toggle='dropdown' aria-haspopup='true' aria-expanded='false'>Updates</a>";
        html += "<div class='dropdown-menu' aria-labelledby='updatesDropdown'>";
        html += "<a class='dropdown-item' href='/update'>Check for new firmware</a>";
       /* html += "<a class='dropdown-item' href='/install_update'>Install New Firmware</a>";*/
        html += "<a class='dropdown-item' href='/toggle_skip_update'>Toggle Skip Update Check " + String(skipUpdateCheck ? "Off" : "On") + "</a>";
        html += "</div>";
        html += "</li>";
        html += "<li class='nav-item dropdown'>";
        html += "<a class='nav-link dropdown-toggle' href='#' id='debugDropdown' role='button' data-toggle='dropdown' aria-haspopup='true' aria-expanded='false'>Debug</a>";
        html += "<div class='dropdown-menu' aria-labelledby='debugDropdown'>";
        html += "<a class='dropdown-item' href='/toggle_debug'>Toggle Serial Debug " + String(debugEnabled ? "Off" : "On") + "</a>";
        html += "<a class='dropdown-item' href='/toggle_web_debug'>Toggle Web Debug " + String(webDebugEnabled ? "Off" : "On") + "</a>";
        html += "<a class='dropdown-item' href='/view_logs'>View Logs</a>";
        html += "<a class='dropdown-item' href='/send_info'>Send Device Info</a>";
        html += "<a class='dropdown-item' href='/send_ping'>Send Ping</a>";
        html += "</div>";
        html += "</li>";
        html += "<li class='nav-item dropdown'>";
        html += "<a class='nav-link dropdown-toggle' href='#' id='settingsDropdown' role='button' data-toggle='dropdown' aria-haspopup='true' aria-expanded='false'>Settings</a>";
        html += "<div class='dropdown-menu' aria-labelledby='settingsDropdown'>";
        html += "<a class='dropdown-item' href='/restart'>Restart Device</a>";
        html += "<a class='dropdown-item' href='/change_password'>Change Password</a>";
        html += "<a class='dropdown-item' href='/change_device_name'>Change Device Name</a>";
        html += "<a class='dropdown-item' href='/set_auth_key'>Set Authentication Key</a>";
        html += "<a class='dropdown-item' href='/manage_wifi'>Manage WiFi</a>";
        html += "<a class='dropdown-item' href='/change_ping_interval'>Change Ping Interval</a>";
        html += "<a class='dropdown-item' href='/change_port'>Change Web Port</a>";
        html += "<a class='dropdown-item' href='/change_ap_duration'>Change AP Mode Duration</a>";
        html += "<a class='dropdown-item' href='/change_deep_sleep_duration'>Change Deep Sleep Duration</a>";
        html += "<a class='dropdown-item' href='/change_reconnect_attempts'>Change Max Reconnect Attempts</a>";
        html += "<a class='dropdown-item' href='/change_reconnect_settings'>Change Reconnect Settings</a>";
        html += "</div>";
        html += "</li>";
        html += "<li class='nav-item'>";
        html += "<a class='nav-link' href='#' data-toggle='modal' data-target='#aboutModal'>About</a>";
        html += "</li>";
        html += "</ul>";
        html += "</div>";
        html += "</nav>";

        // About Modal
        html += "<div class='modal fade' id='aboutModal' tabindex='-1' role='dialog' aria-labelledby='aboutModalLabel' aria-hidden='true'>";
        html += "<div class='modal-dialog' role='document'>";
        html += "<div class='modal-content'>";
        html += "<div class='modal-header'>";
        html += "<h5 class='modal-title' id='aboutModalLabel'>About</h5>";
        html += "<button type='button' class='close' data-dismiss='modal' aria-label='Close'>";
        html += "<span aria-hidden='true'>&times;</span>";
        html += "</button>";
        html += "</div>";
        html += "<div class='modal-body'>";
        html += "<p>Firmware Created By Ioannis Panagou</p>";
        html += "<p>Firmware version: " + String(_fwVersion) + "</p>";
        html += "</div>";
        html += "<div class='modal-footer'>";
        html += "<button type='button' class='btn btn-secondary' data-dismiss='modal'>Close</button>";
        html += "</div>";
        html += "</div>";
        html += "</div>";
        html += "</div>";

        html += "<div class='container mt-3'>";
        html += "<table class='table mt-3'>";
        html += "<tr><th>Device Name</th><td>" + device_name + "</td></tr>";
        html += "<tr><th>Current Access Point</th><td>" + String(WiFi.SSID()) + "</td></tr>";
        html += "<tr><th>Skip Update Check</th><td>" + String(skipUpdateCheck ? "Enabled" : "Disabled") + "</td></tr>";
        html += "<tr><th>Current Time</th><td>" + getCurrentTime() + "</td></tr>";
        html += "<tr><th>Device Uptime</th><td>" + getUptime() + "</td></tr>";
        html += "<tr><th>Firmware Version</th><td>" + String(_fwVersion) + "</td></tr>";
        html += "</table>";
        html += "<button class='btn btn-secondary mt-3' onclick=\"location.reload()\">Refresh</button>";
        if (updateAvailable) {
            html += "<script>alert('New firmware update is available!');</script>";
        }
        html += "</div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/update", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Update Check</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-5'>";
        html += "<div class='card'>";
        html += "<div class='card-header'><h4>Update Check</h4></div>";
        html += "<div class='card-body'>";
        html += "<div class='alert alert-info' role='alert'>";
        html += "<h5>Current version: " + String(_fwVersion) + "</h5>";
        html += "<div class='progress mb-3'>";
        html += "<div class='progress-bar progress-bar-striped progress-bar-animated' role='progressbar' style='width: 100%'></div>";
        html += "</div>";
        html += "<p>Please wait while we check for updates...</p>";
        html += "</div>";
        html += "</div></div>";
        html += "<script>";
        html += "setTimeout(function() {";
        html += "  window.location.href = '/check_update_status';";
        html += "}, 2000);";
        html += "</script>";
        html += "</div></body></html>";
        server->send(200, "text/html", html);
        checkForUpdates();
    });

    server->on("/check_update_status", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }

        // Check auth key
        HTTPClient authHttp;
        authHttp.begin(client, authUrl);
        String jsonPayload = "{\"auth_key\":\"" + authKey + "\"}";
        authHttp.addHeader("Content-Type", "application/json");
        authHttp.addHeader("Authorization", authKey);

        int authResponseCode = authHttp.POST(jsonPayload);
        String authResponse = authHttp.getString();
        debugPrintln("Server response: " + authResponse);
        authHttp.end();

        String html = "<html><head><title>Update Status</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-5'>";
        html += "<div class='card'>";
        html += "<div class='card-header'><h4>Update Check Results</h4></div>";
        html += "<div class='card-body'>";

        if (authResponseCode != 200 || 
            (authResponse.indexOf("\"status\":\"success\"") == -1 && 
             authResponse.indexOf("\"status\":\"approved\"") == -1)) {
            html += "<div class='alert alert-danger' role='alert'>";
            html += "<h5>Authentication Error</h5>";
            html += "<p>The authentication key is not valid. Please check your settings.</p>";
            html += "</div>";
        } else if (updateAvailable) {
            html += "<div class='alert alert-success' role='alert'>";
            html += "<h5>New version found!</h5>";
            html += "<p>You can install the new version now.</p>";
            html += "<a href='/install_update' class='btn btn-primary'>Install Update</a>";
            html += "</div>";
        } else {
            html += "<div class='alert alert-info' role='alert'>";
            html += "<h5>You are up to date!</h5>";
            html += "<p>You already have the latest version (" + String(_fwVersion) + ")</p>";
            html += "</div>";
        }
        html += "</div></div>";
        html += "<a href='/' class='btn btn-secondary mt-3'>Back to main menu</a>";
        html += "</div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/install_update", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }

        // Check auth key
        HTTPClient authHttp;
        authHttp.begin(client, authUrl);
        String jsonPayload = "{\"auth_key\":\"" + authKey + "\"}";
        authHttp.addHeader("Content-Type", "application/json");
        authHttp.addHeader("Authorization", authKey);

        int authResponseCode = authHttp.POST(jsonPayload);
        String authResponse = authHttp.getString();
        debugPrintln("Server response: " + authResponse);
        authHttp.end();

        String html = "<html><head><title>Install Update</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";

        if (authResponseCode != 200 || 
            (authResponse.indexOf("\"status\":\"success\"") == -1 && 
             authResponse.indexOf("\"status\":\"approved\"") == -1)) {
            html += "</head><body>";
            html += "<div class='container mt-5'>";
            html += "<div class='card'>";
            html += "<div class='card-header'><h4>Installation Error</h4></div>";
            html += "<div class='card-body'>";
            html += "<div class='alert alert-danger' role='alert'>";
            html += "<h5>Authentication Error</h5>";
            html += "<p>The authentication key is not valid. The installation has been cancelled.</p>";
            html += "</div>";
            html += "</div></div>";
            html += "<a href='/' class='btn btn-secondary mt-3'>Back to main menu</a>";
            html += "</div></body></html>";
            server->send(200, "text/html", html);
            return;
        }

        if (!updateAvailable) {
            html += "</head><body>";
            html += "<div class='container mt-5'>";
            html += "<div class='card'>";
            html += "<div class='card-header'><h4>Installation Error</h4></div>";
            html += "<div class='card-body'>";
            html += "<div class='alert alert-warning' role='alert'>";
            html += "<h5>No Update Available</h5>";
            html += "<p>There is no new version available to install.</p>";
            html += "</div>";
            html += "</div></div>";
            html += "<a href='/' class='btn btn-secondary mt-3'>Back to main menu</a>";
            html += "</div></body></html>";
            server->send(200, "text/html", html);
            return;
        }

        html += "<meta http-equiv='refresh' content='30;url=/'>";
        html += "</head><body>";
        html += "<div class='container mt-5'>";
        html += "<div class='card'>";
        html += "<div class='card-header'><h4>Installing new firmware</h4></div>";
        html += "<div class='card-body'>";
        html += "<div class='alert alert-warning' role='alert'>";
        html += "<h5>The device is being updated</h5>";
        html += "<p>Please do not turn off the device or disconnect the power.</p>";
        html += "<div class='progress mb-3'>";
        html += "<div class='progress-bar progress-bar-striped progress-bar-animated' role='progressbar' style='width: 100%'></div>";
        html += "</div>";
        html += "<p>The device will restart automatically after the update.</p>";
        html += "</div>";
        html += "</div></div>";
        html += "<script>";
        html += "setTimeout(function() {";
        html += "  let attempts = 0;";
        html += "  const maxAttempts = 30;";
        html += "  const checkConnection = function() {";
        html += "    if (attempts >= maxAttempts) {";
        html += "      window.location.href = '/';";
        html += "      return;";
        html += "    }";
        html += "    fetch('/', { method: 'HEAD' })";
        html += "      .then(response => {";
        html += "        if (response.ok) {";
        html += "          window.location.href = '/';";
        html += "        } else {";
        html += "          attempts++;";
        html += "          setTimeout(checkConnection, 1000);";
        html += "        }";
        html += "      })";
        html += "      .catch(() => {";
        html += "        attempts++;";
        html += "        setTimeout(checkConnection, 1000);";
        html += "      });";
        html += "  };";
        html += "  setTimeout(checkConnection, 5000);";
        html += "}, 2000);";
        html += "</script>";
        html += "</div></body></html>";
        server->send(200, "text/html", html);
        installUpdate();
    });

    server->on("/toggle_skip_update", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Toggle Skip Update</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-5'>";
        html += "<div class='card'>";
        html += "<div class='card-header'><h4>Change to the omission of updates regulation</h4></div>";
        html += "<div class='card-body'>";
        skipUpdateCheck = !skipUpdateCheck;
        preferences.putBool("skipUpdateCheck", skipUpdateCheck);
        html += "<div class='alert alert-" + String(skipUpdateCheck ? "warning" : "success") + "' role='alert'>";
        html += "<h5>" + String(skipUpdateCheck ? "Enabled" : "Disabled") + " the omission of updates</h5>";
        html += "<p>The new setting will be applied on the next update check.</p>";
        html += "</div>";
        html += "</div></div>";
        html += "<a href='/' class='btn btn-secondary mt-3'>Back to main menu</a>";
        html += "<script>setTimeout(function() { window.location.href = '/'; }, 3000);</script>";
        html += "</div></body></html>";
        server->send(200, "text/html", html);
    });

    // Debug endpoints
    server->on("/toggle_debug", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        debugEnabled = !debugEnabled;
        preferences.putBool("debugEnabled", debugEnabled);
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/toggle_web_debug", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        webDebugEnabled = !webDebugEnabled;
        preferences.putBool("webDebugEnabled", webDebugEnabled);
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/view_logs", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String logs = htmlEscape(getLogs());
        String html = "<html><head><title>System Logs</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>System Logs</h2>";
        html += "<pre class='bg-light p-3'>" + logs + "</pre>";
        html += "<form action=\"/clear_logs\" method=\"POST\" class='mt-3'><button type='submit' class='btn btn-danger'>Clear Logs</button></form>";
        html += "<a href='/' class='btn btn-primary'>Back to Main Menu</a>";
        html += "</div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/clear_logs", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        clearLogs();
        String html = "<html><body><script>alert('Logs cleared successfully');window.location.href='/view_logs';</script></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/send_info", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        sendDeviceInfo();
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/send_ping", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        sendPing();
        server->sendHeader("Location", "/");
        server->send(303);
    });

    // Settings endpoints
    server->on("/restart", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        preferences.putBool("ota_failed", false);
        skipUpdateCheck = false;
        String html = "<html><head><title>Restarting...</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "<meta http-equiv='refresh' content='10;url=/'>";
        html += "</head><body>";
        html += "<div class='container mt-5'>";
        html += "<div class='alert alert-info' role='alert'>";
        html += "<h4 class='alert-heading'>Restarting the device</h4>";
        html += "<p>The device is restarting. Please wait...</p>";
        html += "<div class='progress'>";
        html += "<div class='progress-bar progress-bar-striped progress-bar-animated' role='progressbar' style='width: 100%'></div>";
        html += "</div>";
        html += "</div>";
        html += "<script>";
        html += "setTimeout(function() {";
        html += "  let attempts = 0;";
        html += "  const maxAttempts = 30;";
        html += "  const checkConnection = function() {";
        html += "    if (attempts >= maxAttempts) {";
        html += "      window.location.href = '/';";
        html += "      return;";
        html += "    }";
        html += "    fetch('/', { method: 'HEAD' })";
        html += "      .then(response => {";
        html += "        if (response.ok) {";
        html += "          window.location.href = '/';";
        html += "        } else {";
        html += "          attempts++;";
        html += "          setTimeout(checkConnection, 1000);";
        html += "        }";
        html += "      })";
        html += "      .catch(() => {";
        html += "        attempts++;";
        html += "        setTimeout(checkConnection, 1000);";
        html += "      });";
        html += "  };";
        html += "  setTimeout(checkConnection, 5000);";
        html += "}, 2000);";
        html += "</script>";
        html += "</div></body></html>";
        server->send(200, "text/html", html);
        delay(1000);
        ESP.restart();
    });

    server->on("/change_password", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Change Password</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Change Web Password</h2>";
        html += "<form action='/save_password' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='new_password'>New Password:</label>";
        html += "<input type='password' class='form-control' id='new_password' name='new_password' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_password", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        if (server->hasArg("new_password")) {
            http_password = server->arg("new_password");
            preferences.putString("web_password", http_password);
        }
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/change_device_name", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String current_name = htmlEscape(preferences.getString("device_name", "My ESP32 Device"));
        String html = "<html><head><title>Change Device Name</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Change Device Name</h2>";
        html += "<form action='/save_device_name' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='device_name'>Device Name:</label>";
        html += "<input type='text' class='form-control' id='device_name' name='device_name' value='" + current_name + "' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_device_name", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        if (server->hasArg("device_name")) {
            preferences.putString("device_name", server->arg("device_name"));
        }
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/set_auth_key", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Set Authentication Key</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Set Authentication Key</h2>";
        html += "<form action='/save_auth_key' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='auth_key'>Authentication Key:</label>";
        html += "<input type='text' class='form-control' id='auth_key' name='auth_key' value='" + authKey + "' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_auth_key", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        if (server->hasArg("auth_key")) {
            authKey = server->arg("auth_key");
            preferences.putString("auth_key", authKey);
        }
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/manage_wifi", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String current_ssid = htmlEscape(preferences.getString("ssid", ""));
        String html = "<html><head><title>Manage WiFi</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "<script src='https://code.jquery.com/jquery-3.5.1.min.js'></script>";
        html += "<style>.network-list { max-height: 300px; overflow-y: auto; }</style>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<div class='card'>";
        html += "<div class='card-header'><h2>Manage WiFi Settings</h2></div>";
        html += "<div class='card-body'>";
        
        // Τρέχουσα κατάσταση WiFi
        html += "<div class='alert " + String(WiFi.status() == WL_CONNECTED ? "alert-success" : "alert-warning") + "'>";
        html += "<h5>WiFi Status:</h5>";
        if (WiFi.status() == WL_CONNECTED) {
            html += "<p>Connected to network: " + WiFi.SSID() + "</p>";
            html += "<p>IP Address: " + WiFi.localIP().toString() + "</p>";
            html += "<p>Signal Strength: " + String(WiFi.RSSI()) + " dBm</p>";
        } else {
            html += "<p>Disconnected</p>";
        }
        html += "</div>";

        html += "<form action='/save_wifi' method='POST' class='mb-4'>";
        html += "<div class='form-group'>";
        html += "<label for='ssid'>SSID:</label>";
        html += "<div class='input-group'>";
        html += "<input type='text' class='form-control' id='ssid' name='ssid' value='" + current_ssid + "' required>";
        html += "<div class='input-group-append'>";
        html += "<button type='button' class='btn btn-info' onclick='scanNetworks()'>Scan Networks</button>";
        html += "</div></div></div>";
        
        // Λίστα διαθέσιμων δικτύων
        html += "<div class='network-list d-none' id='networkList'>";
        html += "<div class='list-group mb-3'></div>";
        html += "</div>";

        html += "<div class='form-group'>";
        html += "<label for='password'>Password:</label>";
        html += "<div class='input-group'>";
        html += "<input type='password' class='form-control' id='password' name='password' required>";
        html += "<div class='input-group-append'>";
        html += "<button type='button' class='btn btn-secondary' onclick='togglePassword()'>Show</button>";
        html += "</div></div></div>";

        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary ml-2'>Cancel</a>";
        html += "</form>";

        // JavaScript για λειτουργικότητα
        html += "<script>";
        html += "function togglePassword() {";
        html += "  var x = document.getElementById('password');";
        html += "  if (x.type === 'password') {";
        html += "    x.type = 'text';";
        html += "  } else {";
        html += "    x.type = 'password';";
        html += "  }";
        html += "}";
        
        html += "function scanNetworks() {";
        html += "  $('#networkList').removeClass('d-none');";
        html += "  $('#networkList .list-group').html('<div class=\"text-center\"><div class=\"spinner-border\" role=\"status\"></div><p>Σάρωση δικτύων...</p></div>');";
        html += "  $.get('/scan_wifi', function(data) {";
        html += "    $('#networkList .list-group').empty();";
        html += "    data.networks.forEach(function(network) {";
        html += "      var item = $('<a href=\"#\" class=\"list-group-item list-group-item-action\">');";
        html += "      item.text(network.ssid + ' (' + network.rssi + ' dBm)');";
        html += "      item.click(function(e) {";
        html += "        e.preventDefault();";
        html += "        $('#ssid').val(network.ssid);";
        html += "      });";
        html += "      $('#networkList .list-group').append(item);";
        html += "    });";
        html += "  });";
        html += "}";
        html += "</script>";

        html += "</div></div></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/scan_wifi", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        
        int n = WiFi.scanNetworks();
        String json = "{\"networks\":[";
        for (int i = 0; i < n; ++i) {
            if (i > 0) json += ",";
            json += "{\"ssid\":\"" + WiFi.SSID(i) + "\",\"rssi\":" + String(WiFi.RSSI(i)) + "}";
        }
        json += "]}";
        server->send(200, "application/json", json);
        WiFi.scanDelete();
    });

    server->on("/save_wifi", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        
        String html = "<html><head><title>Save WiFi Settings</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "<meta http-equiv='refresh' content='10;url=/'>";
        html += "</head><body>";
        html += "<div class='container mt-5'>";
        html += "<div class='card'>";
        html += "<div class='card-header'><h4>Change WiFi Settings</h4></div>";
        html += "<div class='card-body'>";
        
        if (server->hasArg("ssid") && server->hasArg("password")) {
            String newSSID = server->arg("ssid");
            String newPassword = server->arg("password");
            
            preferences.putString("ssid", newSSID);
            preferences.putString("wifi_password", newPassword);
            
            html += "<div class='alert alert-info'>";
            html += "<h5>Change WiFi Settings</h5>";
            html += "<p>Reconnecting to network: " + newSSID + "</p>";
            html += "<div class='progress mb-3'>";
            html += "<div class='progress-bar progress-bar-striped progress-bar-animated' role='progressbar' style='width: 100%'></div>";
            html += "</div>";
            html += "</div>";
            
            WiFi.disconnect();
            WiFi.begin(newSSID.c_str(), newPassword.c_str());
        } else {
            html += "<div class='alert alert-danger'>";
            html += "<h5>Error</h5>";
            html += "<p>Missing required parameters.</p>";
            html += "</div>";
        }
        
        html += "</div></div>";
        html += "<script>";
        html += "setTimeout(function() {";
        html += "  let attempts = 0;";
        html += "  const maxAttempts = 30;";
        html += "  const checkConnection = function() {";
        html += "    if (attempts >= maxAttempts) {";
        html += "      window.location.href = '/';";
        html += "      return;";
        html += "    }";
        html += "    fetch('/', { method: 'HEAD' })";
        html += "      .then(response => {";
        html += "        if (response.ok) {";
        html += "          window.location.href = '/';";
        html += "        } else {";
        html += "          attempts++;";
        html += "          setTimeout(checkConnection, 1000);";
        html += "        }";
        html += "      })";
        html += "      .catch(() => {";
        html += "        attempts++;";
        html += "        setTimeout(checkConnection, 1000);";
        html += "      });";
        html += "  };";
        html += "  setTimeout(checkConnection, 5000);";
        html += "}, 2000);";
        html += "</script>";
        html += "</div></body></html>";
        
        server->send(200, "text/html", html);
    });

    server->on("/change_ping_interval", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Change Ping Interval</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Change Ping Interval</h2>";
        html += "<form action='/save_ping_interval' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='interval'>Ping Interval (minutes):</label>";
        html += "<input type='number' class='form-control' id='interval' name='interval' value='" + String(ping_interval / 60000) + "' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_ping_interval", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        if (server->hasArg("interval")) {
            ping_interval = server->arg("interval").toInt() * 60000;
            preferences.putULong("ping_interval", ping_interval);
        }
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/change_port", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Change Web Port</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Change Web Port</h2>";
        html += "<form action='/save_port' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='port'>Port Number:</label>";
        html += "<input type='number' class='form-control' id='port' name='port' value='" + String(serverPort) + "' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_port", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        
        String html = "<html><head><title>Port Change</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "<meta http-equiv='refresh' content='10;url=/'>";
        html += "</head><body>";
        html += "<div class='container mt-5'>";
        html += "<div class='card'>";
        html += "<div class='card-header'><h4>Port Change</h4></div>";
        html += "<div class='card-body'>";
        
        if (server->hasArg("port")) {
            int newPort = server->arg("port").toInt();
            if (newPort >= 1 && newPort <= 65535) {
                serverPort = newPort;
                preferences.putInt("serverPort", serverPort);
                
                html += "<div class='alert alert-success'>";
                html += "<h5>Success</h5>";
                html += "<p>The new port is set to: " + String(serverPort) + "</p>";
                html += "<div class='progress mb-3'>";
                html += "<div class='progress-bar progress-bar-striped progress-bar-animated' role='progressbar' style='width: 100%'></div>";
                html += "</div>";
                html += "<p>The server will be restarted with the new port...</p>";
                html += "</div>";
                
                // Επανεκκίνηση του server με τη νέα θύρα (χωρίς διαρροές)
                if (server != nullptr) {
                    server->close();
                    delete server;
                    server = nullptr;
                }
                server = new WebServer(serverPort);
                initializeServer();
            } else {
                html += "<div class='alert alert-danger'>";
                html += "<h5>Error</h5>";
                html += "<p>Invalid port. Please enter a number between 1 and 65535.</p>";
                html += "</div>";
            }
        } else {
            html += "<div class='alert alert-danger'>";
            html += "<h5>Error</h5>";
            html += "<p>No port was specified.</p>";
            html += "</div>";
        }
        
        html += "</div></div>";
        html += "<script>";
        html += "setTimeout(function() {";
        html += "  let attempts = 0;";
        html += "  const maxAttempts = 30;";
        html += "  const checkConnection = function() {";
        html += "    if (attempts >= maxAttempts) {";
        html += "      window.location.href = '/';";
        html += "      return;";
        html += "    }";
        html += "    fetch('/', { method: 'HEAD' })";
        html += "      .then(response => {";
        html += "        if (response.ok) {";
        html += "          window.location.href = '/';";
        html += "        } else {";
        html += "          attempts++;";
        html += "          setTimeout(checkConnection, 1000);";
        html += "        }";
        html += "      })";
        html += "      .catch(() => {";
        html += "        attempts++;";
        html += "        setTimeout(checkConnection, 1000);";
        html += "      });";
        html += "  };";
        html += "  setTimeout(checkConnection, 5000);";
        html += "}, 2000);";
        html += "</script>";
        html += "</div></body></html>";
        
        server->send(200, "text/html", html);
    });

    server->on("/change_ap_duration", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Change AP Mode Duration</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Change AP Mode Duration</h2>";
        html += "<form action='/save_ap_duration' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='duration'>Duration (minutes):</label>";
        html += "<input type='number' class='form-control' id='duration' name='duration' value='" + String(AP_MODE_DURATION / 60000) + "' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_ap_duration", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        if (server->hasArg("duration")) {
            AP_MODE_DURATION = server->arg("duration").toInt() * 60000;
            setAPModeDuration(AP_MODE_DURATION);
        }
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/change_deep_sleep_duration", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Change Deep Sleep Duration</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Change Deep Sleep Duration</h2>";
        html += "<form action='/save_deep_sleep_duration' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='duration'>Duration (minutes):</label>";
        html += "<input type='number' class='form-control' id='duration' name='duration' value='" + String(DEEP_SLEEP_DURATION / 60000000) + "' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_deep_sleep_duration", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        if (server->hasArg("duration")) {
            DEEP_SLEEP_DURATION = server->arg("duration").toInt() * 60000000;
            setDeepSleepDuration(DEEP_SLEEP_DURATION);
        }
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/change_reconnect_attempts", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Change Max Reconnect Attempts</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Change Max Reconnect Attempts</h2>";
        html += "<form action='/save_reconnect_attempts' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='attempts'>Maximum Attempts:</label>";
        html += "<input type='number' class='form-control' id='attempts' name='attempts' value='" + String(MAX_RECONNECT_ATTEMPTS) + "' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_reconnect_attempts", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        if (server->hasArg("attempts")) {
            MAX_RECONNECT_ATTEMPTS = server->arg("attempts").toInt();
            setMaxReconnectAttempts(MAX_RECONNECT_ATTEMPTS);
        }
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->on("/change_reconnect_settings", HTTP_GET, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        String html = "<html><head><title>Change Reconnect Settings</title>";
        html += "<link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>";
        html += "</head><body>";
        html += "<div class='container mt-3'>";
        html += "<h2>Change Reconnect Settings</h2>";
        html += "<form action='/save_reconnect_settings' method='POST'>";
        html += "<div class='form-group'>";
        html += "<label for='interval'>Initial Reconnect Interval (ms):</label>";
        html += "<input type='number' class='form-control' id='interval' name='interval' value='" + String(reconnect_attempt_interval) + "' required>";
        html += "</div>";
        html += "<div class='form-group'>";
        html += "<label for='max_interval'>Maximum Reconnect Interval (ms):</label>";
        html += "<input type='number' class='form-control' id='max_interval' name='max_interval' value='" + String(max_reconnect_attempt_interval) + "' required>";
        html += "</div>";
        html += "<button type='submit' class='btn btn-primary'>Save</button>";
        html += "<a href='/' class='btn btn-secondary'>Cancel</a>";
        html += "</form></div></body></html>";
        server->send(200, "text/html", html);
    });

    server->on("/save_reconnect_settings", HTTP_POST, [this]() {
        if (!server->authenticate(http_username.c_str(), http_password.c_str())) {
            return server->requestAuthentication();
        }
        if (server->hasArg("interval") && server->hasArg("max_interval")) {
            reconnect_attempt_interval = server->arg("interval").toInt();
            max_reconnect_attempt_interval = server->arg("max_interval").toInt();
            setReconnectInterval(reconnect_attempt_interval);
            setMaxReconnectInterval(max_reconnect_attempt_interval);
        }
        server->sendHeader("Location", "/");
        server->send(303);
    });

    server->begin();
}

bool ICP_ESP32::validateAuthKey() {
    if (authKey == nullptr || authKey.length() == 0) {
        debugPrintln("Σφάλμα: Το κλειδί πιστοποίησης δεν έχει οριστεί.");
        return false;
    }

    if (WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.begin(client, authUrl);

        String jsonPayload = "{\"auth_key\":\"" + authKey + "\"}";
        debugPrintln("Επικύρωση κλειδιού πιστοποίησης...");

        http.addHeader("Content-Type", "application/json");
        http.addHeader("Authorization", authKey);

        int httpResponseCode = http.POST(jsonPayload);
        String response = http.getString();
        debugPrintln("Απάντηση server: " + response);
        http.end();

        if (httpResponseCode == 200) {
            if (response.indexOf("\"status\":\"success\"") != -1 || 
                response.indexOf("\"status\":\"approved\"") != -1 || 
                response.indexOf("\"valid\":true") != -1 || 
                response.indexOf("\"status\": \"success\"") != -1 || 
                response.indexOf("\"status\": \"approved\"") != -1 || 
                response.indexOf("\"valid\": true") != -1) {
                debugPrintln("Το κλειδί πιστοποίησης είναι έγκυρο.");
                return true;
            }
            debugPrintln("Το κλειδί πιστοποίησης δεν είναι έγκυρο (μη αναμενόμενη απάντηση).");
            return false;
        } else if (httpResponseCode == 401) {
            debugPrintln("Αποτυχία επικύρωσης κλειδιού: Μη εξουσιοδοτημένο (401).");
            return false;
        } else {
            debugPrintln("Αποτυχία επικύρωσης κλειδιού με κωδικό απόκρισης: " + String(httpResponseCode));
            return false;
        }
    } else {
        debugPrintln("Το WiFi δεν είναι συνδεδεμένο. Δεν είναι δυνατή η επικύρωση του κλειδιού.");
        return false;
    }
}

void ICP_ESP32::loop() {
    esp_sleep_wakeup_cause_t wakeup_reason = esp_sleep_get_wakeup_cause();
    if (wakeup_reason == ESP_SLEEP_WAKEUP_TIMER) {
        debugPrintln("Waking up from a deep sleep due to a stopwatch");
        delay(1000);
        ESP.restart();
    }

    server->handleClient();

    if (in_ap_mode) {
        if (millis() - ap_mode_start_time >= AP_MODE_DURATION) {
            debugPrintln("AP mode duration expired. Switching to deep sleep mode...");
            WiFi.softAPdisconnect(true);
            in_ap_mode = false;
            delay(1000);
            enterDeepSleepMode();
        }
        return; // Σταματάμε εδώ όταν είμαστε σε AP Mode
    }

    if (wifiAttemptInProgress) {
        if (WiFi.status() == WL_CONNECTED) {
            if (in_ap_mode) {
                WiFi.softAPdisconnect(true);
                WiFi.mode(WIFI_STA);
                in_ap_mode = false;
                debugPrintln("AP mode disabled due to successful WiFi connection.");
            }
            debugPrintln("WiFi connected: " + WiFi.SSID());
            wifiAttemptInProgress = false;
            if (!wifiInitialized) {
                client.setCACert(rootCACertificate);
                setClock();
                sendDeviceInfo();
                if (validateAuthKey()) {
                    if (!skipUpdateCheck) {
                        checkForUpdatesAndUpdateIfNeeded();
                    } else {
                        debugPrintln("Skipping firmware update check due to previous OTA failure.");
                    }
                } else {
                    debugPrintln("Invalid auth key. Skipping update check.");
                }
                initializeServer();
                sendPing();
                wifiInitialized = true;
            }
        }
        else if (millis() - wifiConnectStartTime > wifiConnectTimeout) {
            debugPrintln("WiFi connection timed out. Switching to AP mode...");
            wifiAttemptInProgress = false;
            startAPMode();
        }
    }
    else {
        if (WiFi.status() != WL_CONNECTED && !in_ap_mode) {
            reconnectToWiFi();
        }
    }

    if (millis() - last_ping_time >= ping_interval) {
        sendPing();
        last_ping_time = millis();
    }

    if (digitalRead(_resetButtonPin) == LOW) {
        if (!isButtonPressed) {
            isButtonPressed = true;
            buttonPressStartTime = millis();
        } else if (millis() - buttonPressStartTime >= 10000) {
            resetToDefault();
        }
    } else {
        isButtonPressed = false;
    }
}

// Configuration methods
void ICP_ESP32::setAPModeDuration(unsigned long duration) {
    AP_MODE_DURATION = duration;
    EEPROM.put(AP_DURATION_ADDR, AP_MODE_DURATION);
    EEPROM.commit();
}

void ICP_ESP32::setDeepSleepDuration(unsigned long duration) {
    DEEP_SLEEP_DURATION = duration;
    EEPROM.put(DEEP_SLEEP_DURATION_ADDR, DEEP_SLEEP_DURATION);
    EEPROM.commit();
}

void ICP_ESP32::setMaxReconnectAttempts(unsigned int attempts) {
    MAX_RECONNECT_ATTEMPTS = attempts;
    EEPROM.put(RECONNECT_ATTEMPTS_ADDR, MAX_RECONNECT_ATTEMPTS);
    EEPROM.commit();
}

void ICP_ESP32::setReconnectInterval(unsigned long interval) {
    reconnect_attempt_interval = interval;
    EEPROM.put(RECONNECT_INTERVAL_ADDR, reconnect_attempt_interval);
    EEPROM.commit();
}

void ICP_ESP32::setMaxReconnectInterval(unsigned long interval) {
    max_reconnect_attempt_interval = interval;
    EEPROM.put(MAX_RECONNECT_INTERVAL_ADDR, max_reconnect_attempt_interval);
    EEPROM.commit();
}

// Status methods
bool ICP_ESP32::isConnected() {
    return WiFi.status() == WL_CONNECTED;
}

String ICP_ESP32::getDeviceName() {
    return preferences.getString("device_name", "My ESP32 Device");
}

String ICP_ESP32::getCurrentTime() {
    time_t now = time(nullptr);
    struct tm timeinfo;
    gmtime_r(&now, &timeinfo);
    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return String(buffer);
}

String ICP_ESP32::getUptime() {
    unsigned long now = millis();
    unsigned long uptime = now - bootTime;
    unsigned long seconds = uptime / 1000;
    unsigned long minutes = seconds / 60;
    unsigned long hours = minutes / 60;
    unsigned long days = hours / 24;
    seconds %= 60;
    minutes %= 60;
    hours %= 24;
    char buffer[40];
    if (days > 0) {
        sprintf(buffer, "%lu days %02lu:%02lu:%02lu", days, hours, minutes, seconds);
    } else {
        sprintf(buffer, "%02lu:%02lu:%02lu", hours, minutes, seconds);
    }
    return String(buffer);
} 