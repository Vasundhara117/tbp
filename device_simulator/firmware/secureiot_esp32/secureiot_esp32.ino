
#include <WiFi.h>
#include <HTTPClient.h>
#include <time.h>
#include <sys/time.h>

// Configure these values for your test network.
const char* WIFI_SSID = " WIFI NAME";
const char* WIFI_PASSWORD = "PASSWORD";

// Backend URL: use the laptop's LAN IP, not localhost.
const char* SERVER_URL =
    "http://192.168.29.38:8000/api/v1/messages";

const char* DEVICE_ID = "CCTV-ESP32-01";
const char* DEVICE_TYPE = "cctv_simulator";

const unsigned long NORMAL_INTERVAL_MS = 5000;
const unsigned long BURST_INTERVAL_MS = 200;
const unsigned long DEFAULT_BURST_SECONDS = 10;
const unsigned long MAX_BURST_SECONDS = 300;

unsigned long messageNumber = 0;
unsigned long lastMessageTime = 0;
unsigned long burstStartedAt = 0;
unsigned long burstDurationMs = 0;

bool burstMode = false;
bool clockSynced = false;

void sendHeartbeat() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Wi-Fi disconnected; message skipped.");
    return;
  }

  if (!clockSynced) {
    Serial.println("Clock not synchronized; message skipped.");
    return;
  }

  struct timeval tv;
  gettimeofday(&tv, nullptr);

  long long timestampMs =
      (long long)tv.tv_sec * 1000LL + tv.tv_usec / 1000;

  char messageId[32];
  snprintf(messageId, sizeof(messageId),
           "msg-%04lu", ++messageNumber);

  String body = "{\"device_id\":\"" + String(DEVICE_ID) +
      "\",\"device_type\":\"" + String(DEVICE_TYPE) +
      "\",\"message_id\":\"" + String(messageId) +
      "\",\"timestamp_ms\":" + String(timestampMs) +
      ",\"data\":{\"status\":\"online\","
      "\"activity\":\"heartbeat\"}}";

  HTTPClient http;
  http.setConnectTimeout(1000);
  http.setTimeout(1000);

  if (!http.begin(SERVER_URL)) {
    Serial.println("HTTP initialization failed.");
    return;
  }

  http.addHeader("Content-Type", "application/json");
  int statusCode = http.POST(body);

  Serial.printf("%s | HTTP status: %d\n",
                messageId, statusCode);

  if (statusCode > 0) {
    Serial.println(http.getString());
  } else {
    Serial.println(http.errorToString(statusCode));
  }

  http.end();
}

void startBurst(unsigned long seconds) {
  if (seconds == 0 || seconds > MAX_BURST_SECONDS) {
    Serial.println("Duration must be 1-300 seconds.");
    return;
  }

  burstDurationMs = seconds * 1000UL;
  burstStartedAt = millis();
  lastMessageTime = millis() - BURST_INTERVAL_MS;
  burstMode = true;

  Serial.printf("BURST mode started for %lu seconds.\n", seconds);
  Serial.println("Target interval: 200 ms.");
}

void processCommand(String command) {
  command.trim();
  command.toUpperCase();

  if (command == "NORMAL") {
    burstMode = false;
    lastMessageTime = millis();
    Serial.println("NORMAL mode: heartbeat every 5 seconds.");
    return;
  }

  if (command == "BURST" || command.startsWith("BURST ")) {
    unsigned long seconds = DEFAULT_BURST_SECONDS;

    if (command.startsWith("BURST ")) {
      String durationText = command.substring(6);
      durationText.trim();

      if (durationText.length() == 0) {
        Serial.println("Usage: BURST or BURST <seconds>");
        return;
      }

      for (unsigned int i = 0; i < durationText.length(); i++) {
        if (!isDigit(durationText[i])) {
          Serial.println("Duration must be a whole number.");
          return;
        }
      }

      seconds = durationText.toInt();
    }

    startBurst(seconds);
    return;
  }

  if (command.length() > 0) {
    Serial.println("Commands: NORMAL, BURST, BURST <seconds>");
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\nSecureIoT Sentinel starting...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  Serial.print("Connecting to Wi-Fi...");
  unsigned long started = millis();

  while (WiFi.status() != WL_CONNECTED &&
         millis() - started < 20000) {
    delay(500);
    Serial.print(".");
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\nWi-Fi connection failed. Restart after fixing Wi-Fi.");
    return;
  }

  Serial.println("\nWi-Fi connected!");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());

  configTime(0, 0, "pool.ntp.org", "time.google.com");

  struct tm timeInfo = {};
  started = millis();

  while (!getLocalTime(&timeInfo, 500) &&
         millis() - started < 15000) {
    Serial.print(".");
  }

  clockSynced = getLocalTime(&timeInfo, 100);

  if (clockSynced) {
    Serial.println("\nClock synchronized!");
  } else {
    Serial.println("\nClock sync failed; restart and retry.");
  }

  Serial.println("\nCommands: NORMAL, BURST, BURST <seconds>");
  lastMessageTime = millis();
}

void loop() {
  while (Serial.available()) {
    processCommand(Serial.readStringUntil('\n'));
  }

  if (WiFi.status() != WL_CONNECTED) {
    static unsigned long lastReconnectAttempt = 0;

    if (millis() - lastReconnectAttempt >= 5000) {
      lastReconnectAttempt = millis();
      Serial.println("Wi-Fi disconnected; attempting reconnect.");
      WiFi.reconnect();
    }

    delay(10);
    return;
  }

  unsigned long now = millis();

  if (burstMode && now - burstStartedAt >= burstDurationMs) {
    burstMode = false;
    lastMessageTime = now;
    Serial.println("BURST complete. Returning to NORMAL mode.");
  }

  unsigned long interval =
      burstMode ? BURST_INTERVAL_MS : NORMAL_INTERVAL_MS;

  if (now - lastMessageTime >= interval) {
    lastMessageTime = now;
    sendHeartbeat();
  }

  delay(2);
}
