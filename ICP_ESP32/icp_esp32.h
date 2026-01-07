#ifndef ICP_ESP32_H
#define ICP_ESP32_H

#include <WiFi.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <Preferences.h>
#include <esp_ota_ops.h>
#include <time.h>
#include <esp_sleep.h>
#include <driver/rtc_cntl.h>
#include <driver/gpio.h>
#include <EEPROM.h>
#include "esp32_board_config.h"

class ICP_ESP32 {
public:
    // Constructor
    ICP_ESP32(int ledPin = ESP32BoardConfig::getDefaultLedPin(), 
              int resetButtonPin = ESP32BoardConfig::getDefaultResetPin(), 
              int fwVersion = 1);
    // Destructor
    ~ICP_ESP32();
    
    // Initialize the device
    void begin();
    
    // Main loop function
    void loop();
    
    // Configuration methods
    void setAPModeDuration(unsigned long duration);
    void setDeepSleepDuration(unsigned long duration);
    void setMaxReconnectAttempts(unsigned int attempts);
    void setReconnectInterval(unsigned long interval);
    void setMaxReconnectInterval(unsigned long interval);
    
    // Status methods
    bool isConnected();
    String getDeviceName();
    String getCurrentTime();
    String getUptime();
    String getBoardType() { return ESP32BoardConfig::getBoardName(); }
    
private:
    // Pin configurations
    int _ledPin;
    int _resetButtonPin;
    int _fwVersion;
    ESP32BoardType _boardType;
    
    // WiFi and server
    WiFiClientSecure client;
    WebServer* server;
    int serverPort;
    Preferences preferences;
    
    // URLs and authentication
    const char* fwUrlBase;
    const char* postUrl;
    const char* pingUrl;
    const char* authUrl;
    String authKey;
    String http_username;
    String http_password;
    
    // Timing variables
    unsigned long target_time;
    const unsigned long PERIOD;
    unsigned long ping_interval;
    unsigned long last_ping_time;
    unsigned long bootTime;
    
    // State variables
    bool skipUpdateCheck;
    bool debugEnabled;
    bool webDebugEnabled;
    bool updateAvailable;
    bool isButtonPressed;
    unsigned long buttonPressStartTime;
    
    // WiFi connection variables
    unsigned long wifiConnectStartTime;
    bool wifiAttemptInProgress;
    bool wifiInitialized;
    const unsigned long wifiConnectTimeout;
    
    // Reconnection variables
    unsigned long last_reconnect_attempt;
    unsigned long ap_mode_start_time;
    bool in_ap_mode;
    unsigned int reconnect_attempts;
    unsigned int MAX_RECONNECT_ATTEMPTS;
    unsigned long reconnect_attempt_interval;
    unsigned long max_reconnect_attempt_interval;
    
    // Mode durations
    unsigned long AP_MODE_DURATION;
    unsigned long DEEP_SLEEP_DURATION;
    
    // EEPROM addresses
    static const int EEPROM_SIZE = 512;
    static const int AP_DURATION_ADDR = 0;
    static const int DEEP_SLEEP_DURATION_ADDR = 4;
    static const int RECONNECT_ATTEMPTS_ADDR = 8;
    static const int RECONNECT_INTERVAL_ADDR = 12;
    static const int MAX_RECONNECT_INTERVAL_ADDR = 16;
    
    // Private methods
    void setup();
    void connectToWiFi();
    void startWiFiConnection();
    void enterDeepSleepMode();
    void reconnectToWiFi();
    void WiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info);
    void debugPrint(String message);
    void debugPrintln(String message);
    String getMAC();
    String getIPAddress();
    String getExternalIPAddress();
    void sendDeviceInfo();
    void checkForUpdates();
    void checkForUpdatesAndUpdateIfNeeded();
    void installUpdate();
    void sendPing();
    void rollbackToFirmware();
    void startAPMode();
    void setClock();
    void resetToDefault();
    void initializeServer();
    bool validateAuthKey();
    
    // Logs (RAM ring buffer)
    void appendLog(const String &message);
    String getLogs();
    void clearLogs();

    // Helpers
    String htmlEscape(const String &in);
    String jsonEscape(const String &in);
};

#endif // ICP_ESP32_H 