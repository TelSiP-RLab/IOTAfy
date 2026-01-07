#ifndef ESP32_BOARD_CONFIG_H
#define ESP32_BOARD_CONFIG_H

#include <Arduino.h>

// Ορισμός των διαφορετικών τύπων πλακετών
enum class ESP32BoardType {
    ESP32,
    ESP32_S3,
    ESP32_C3,
    ESP32_C6
};

// Κλάση για τη διαχείριση της διαμόρφωσης της πλακέτας
class ESP32BoardConfig {
public:
    static ESP32BoardType detectBoardType() {
        #if defined(CONFIG_IDF_TARGET_ESP32S3)
            return ESP32BoardType::ESP32_S3;
        #elif defined(CONFIG_IDF_TARGET_ESP32C3)
            return ESP32BoardType::ESP32_C3;
        #elif defined(CONFIG_IDF_TARGET_ESP32C6)
            return ESP32BoardType::ESP32_C6;
        #else
            return ESP32BoardType::ESP32;
        #endif
    }

    static bool hasUSBCDC() {
        auto board = detectBoardType();
        return board == ESP32BoardType::ESP32_S3 || 
               board == ESP32BoardType::ESP32_C3 ||
               board == ESP32BoardType::ESP32_C6;
    }

    static uint8_t getDefaultLedPin() {
        switch(detectBoardType()) {
            case ESP32BoardType::ESP32_S3:
                return 48; // Προεπιλεγμένο LED pin για ESP32-S3
            case ESP32BoardType::ESP32_C3:
                return 8;  // Προεπιλεγμένο LED pin για ESP32-C3
            case ESP32BoardType::ESP32_C6:
                return 8;  // Προεπιλεγμένο LED pin για ESP32-C6 (ίδιο με C3)
            default:
                return 2;  // Προεπιλεγμένο LED pin για ESP32
        }
    }

    static uint8_t getDefaultResetPin() {
        switch(detectBoardType()) {
            case ESP32BoardType::ESP32_S3:
                return 0;  // Reset button pin για ESP32-S3
            case ESP32BoardType::ESP32_C3:
                return 9;  // Reset button pin για ESP32-C3
            case ESP32BoardType::ESP32_C6:
                return 9;  // Reset button pin για ESP32-C6 (ίδιο με C3)
            default:
                return 0;  // Reset button pin για ESP32
        }
    }

    static uint8_t getDefaultSerialTX() {
        switch(detectBoardType()) {
            case ESP32BoardType::ESP32_S3:
                return 43;  // TX pin για ESP32-S3
            case ESP32BoardType::ESP32_C3:
                return 21;  // TX pin για ESP32-C3
            case ESP32BoardType::ESP32_C6:
                return 21;  // TX pin για ESP32-C6 (ίδιο με C3)
            default:
                return 1;   // TX pin για ESP32
        }
    }

    static uint8_t getDefaultSerialRX() {
        switch(detectBoardType()) {
            case ESP32BoardType::ESP32_S3:
                return 44;  // RX pin για ESP32-S3
            case ESP32BoardType::ESP32_C3:
                return 20;  // RX pin για ESP32-C3
            case ESP32BoardType::ESP32_C6:
                return 20;  // RX pin για ESP32-C6 (ίδιο με C3)
            default:
                return 3;   // RX pin για ESP32
        }
    }

    static const char* getBoardName() {
        switch(detectBoardType()) {
            case ESP32BoardType::ESP32_S3:
                return "ESP32-S3";
            case ESP32BoardType::ESP32_C3:
                return "ESP32-C3";
            case ESP32BoardType::ESP32_C6:
                return "ESP32-C6";
            default:
                return "ESP32";
        }
    }

    static bool hasSecureElement() {
        return detectBoardType() == ESP32BoardType::ESP32_S3;
    }

    static uint32_t getFlashSize() {
        switch(detectBoardType()) {
            case ESP32BoardType::ESP32_S3:
                return 16 * 1024 * 1024; // 16MB για ESP32-S3
            case ESP32BoardType::ESP32_C3:
                return 4 * 1024 * 1024;  // 4MB για ESP32-C3
            case ESP32BoardType::ESP32_C6:
                return 4 * 1024 * 1024;  // 4MB για ESP32-C6
            default:
                return 4 * 1024 * 1024;  // 4MB για ESP32
        }
    }

    static uint32_t getMaxClockSpeed() {
        switch(detectBoardType()) {
            case ESP32BoardType::ESP32_S3:
                return 240000000; // 240MHz για ESP32-S3
            case ESP32BoardType::ESP32_C3:
                return 160000000; // 160MHz για ESP32-C3
            case ESP32BoardType::ESP32_C6:
                return 160000000; // 160MHz για ESP32-C6
            default:
                return 240000000; // 240MHz για ESP32
        }
    }
};

#endif // ESP32_BOARD_CONFIG_H 