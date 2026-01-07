#include "icp_esp32.h"

// Δημιουργία αντικειμένου ICP_ESP32 με συγκεκριμένες παραμέτρους
// LED Pin = 8 (για ESP32-C3)
// LED Pin = 8 (για ESP32-C6)
// LED Pin = 48 (για ESP32-S3)
// Reset Button Pin = 0
// Firmware Version = 79
ICP_ESP32 icp(48, 0, 81);

void setup() {
    // Αρχικοποίηση της συσκευής
    icp.begin();
    
    // Εκτύπωση πληροφοριών για την πλακέτα
    Serial.print("Τύπος πλακέτας: ");
    Serial.println(icp.getBoardType());
}

void loop() {
    // Εκτέλεση του βασικού loop της συσκευής
    icp.loop();
    
    // Έλεγχος αν η συσκευή είναι συνδεδεμένη
    if (icp.isConnected()) {
        // Εκτύπωση πληροφοριών για την πλακέτα
        Serial.print("Τύπος πλακέτας: ");
        Serial.println(icp.getBoardType());
        Serial.println("Κατάσταση συσκευής:");
        Serial.print("- Όνομα συσκευής: ");
        Serial.println(icp.getDeviceName());
        Serial.print("- Χρόνος λειτουργίας: ");
        Serial.println(icp.getUptime());
        Serial.print("- Τρέχουσα ώρα: ");
        Serial.println(icp.getCurrentTime());
    }
    
    delay(5000); // Καθυστέρηση 5 δευτερολέπτων
} 