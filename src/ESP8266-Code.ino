#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <TOTP.h>

const char* WIFI_SSID = "Zekeriya Wifi";
const char* WIFI_PASS = "12345678";

// Secret (20 byte) — seninki
uint8_t secret[] = {
  0x11, 0x22, 0x33, 0x44, 0x55,
  0x66, 0x77, 0x88, 0x99, 0xAA,
  0xBB, 0xCC, 0xDD, 0xEE, 0xF0,
  0x0F, 0x12, 0x34, 0x56, 0x78
};
TOTP totp(secret, sizeof(secret));

// ===== NTP =====
WiFiUDP udp;
const char* NTP_SERVER = "pool.ntp.org";
const int NTP_PORT = 123;

unsigned long baseUnix = 0;        // UTC unix at sync moment
unsigned long baseMillis = 0;      // millis at sync moment
unsigned long lastSyncMillis = 0;

unsigned long getNtpTimeUTC() {
  const int NTP_PACKET_SIZE = 48;
  byte packetBuffer[NTP_PACKET_SIZE];
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  packetBuffer[0] = 0b11100011;

  udp.begin(2390);
  udp.beginPacket(NTP_SERVER, NTP_PORT);
  udp.write(packetBuffer, NTP_PACKET_SIZE);
  udp.endPacket();

  unsigned long start = millis();
  while (millis() - start < 1500) {
    int size = udp.parsePacket();
    if (size >= NTP_PACKET_SIZE) {
      udp.read(packetBuffer, NTP_PACKET_SIZE);

      unsigned long secs1900 =
        ((unsigned long)packetBuffer[40] << 24) |
        ((unsigned long)packetBuffer[41] << 16) |
        ((unsigned long)packetBuffer[42] << 8)  |
        ((unsigned long)packetBuffer[43]);

      const unsigned long SEVENTY_YEARS = 2208988800UL;
      return secs1900 - SEVENTY_YEARS; // UTC
    }
    delay(10);
  }
  return 0;
}

bool syncTime() {
  unsigned long t = getNtpTimeUTC();
  if (t == 0) return false;
  baseUnix = t;
  baseMillis = millis();
  lastSyncMillis = baseMillis;
  return true;
}

unsigned long unixNow() {
  if (baseUnix == 0) return 0;
  unsigned long elapsedSec = (millis() - baseMillis) / 1000UL;
  return baseUnix + elapsedSec;
}

// ===== Verify (±1 pencere toleransı) =====
bool verifyTotp6(const char* code6) {
  unsigned long t = unixNow();
  if (t == 0) return false;

  // 30 saniyelik pencere: current, previous, next
  const unsigned long step = 30UL;

  char* c0 = totp.getCode(t);
  if (strncmp(c0, code6, 6) == 0) return true;

  char* cPrev = totp.getCode(t >= step ? (t - step) : t);
  if (strncmp(cPrev, code6, 6) == 0) return true;

  char* cNext = totp.getCode(t + step);
  if (strncmp(cNext, code6, 6) == 0) return true;

  return false;
}

void setup() {
  Serial.begin(9600);
  Serial.println();
  Serial.println("ESP TOTP verifier basliyor...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
  }

  syncTime();
}

// Serial komut:
//   V123456\n  -> OK / NO
// (İsteğe bağlı debug: "P\n" -> current TOTP basar)
void loop() {
  // 10 dakikada bir yeniden NTP sync
  if (baseUnix != 0 && (millis() - lastSyncMillis) > 600000UL) {
    syncTime();
  }

  static char buf[24];
  static byte idx = 0;

  while (Serial.available()) {
    char c = (char)Serial.read();

    if (c == '\n' || c == '\r') {
      buf[idx] = '\0';
      idx = 0;

      // Debug komutu
      if (strcmp(buf, "P") == 0) {
        unsigned long t = unixNow();
        Serial.print("TOTP:");
        Serial.println(totp.getCode(t));
        return;
      }

      // Verify komutu: Vxxxxxx
      if (buf[0] == 'V' && strlen(buf) == 7) {
        const char* code6 = buf + 1;
        if (verifyTotp6(code6)) Serial.println("OK");
        else Serial.println("NO");
      } else {
        Serial.println("ERR");
      }
      return;
    }

    if (idx < sizeof(buf) - 1) buf[idx++] = c;
  }
}
