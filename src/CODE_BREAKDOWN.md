# Code Breakdown (No Changes)

This document separates the existing source code into readable sections without modifying any code.

## 1) Arduino Main Code
File: `src/Arduino-Code.ino`

## 2) ESP8266 2FA Code
File: `src/ESP8266-Code.ino`

---

# Arduino-Code.ino (Sectioned)

## A) Libraries & Includes

#include <IRremote.h>
#include <LiquidCrystal_I2C.h>
#include <SD.h>
#include <SPI.h>
#include <SoftwareSerial.h>

---

## B) Global Variables / Definitions

// ------------------ LCD ------------------
LiquidCrystal_I2C lcd(0x27, 16, 2);

// ------------------ PINLER ------------------
#define IR_PIN 2
#define BUZZER_PIN 8
#define LED_GREEN  9
#define LED_YELLOW 10
#define LED_RED    7

// ------------------ ESP (TOTP Verify) ------------------
// UNO D5 = RX (ESP TX buraya)
// UNO D6 = TX (ESP RX buradan, direnç bölücü ile!)
SoftwareSerial espSerial(5, 6);
#define OTP_LEN 6
#define OTP_MAX_ATTEMPTS 3

char enteredOtp[OTP_LEN + 1];
byte otpIndex = 0;
byte otpAttempts = 0;

// ------------------ SD ------------------
#define SD_CS_PIN 4
#define SD_FILE_NAME "blocks.txt"
bool sdReady = false;
uint16_t blockIndex = 0;     // next index to write
uint32_t prevBlockHash = 0;  // last block hash

// ------------------ SABİTLER ------------------
#define PIN_LENGTH 4
#define MAX_ATTEMPTS 3
#define LOCK_TIME 30000UL

#define LOCK_BLINK_NORMAL_MS 500UL
#define LOCK_BLINK_FAST_MS   150UL
#define LOCK_FAST_LAST_SEC   5

// ------------------ STATE MACHINE ------------------
enum State { LOCKED, TIME_LOCK, TWO_FA, MENU, TX_INPUT, TX_CONFIRM, LOG_CLEAR_CONFIRM };
State currentState = LOCKED;

// ------------------ PIN ------------------
char enteredPin[PIN_LENGTH + 1];
const char correctPin[] = "1234";
byte pinIndex = 0;
byte attempts = 0;
unsigned long lockStartTime = 0;

// ------------------ MENU (PROGMEM) ------------------
const char menu0[] PROGMEM = "Islem Goster";
const char menu1[] PROGMEM = "Yeni Islem";
const char menu2[] PROGMEM = "Log Sil";
const char menu3[] PROGMEM = "Cikis";
const char* const menuItems[] PROGMEM = { menu0, menu1, menu2, menu3 };
#define MENU_COUNT 4

byte menuIndex = 0;
bool viewingTx = false;

// ------------------ TRANSACTION (RAM cache) ------------------
char amountBuffer[6];       // last amount
byte amountIndex = 0;
unsigned long fakeSignature = 0;  // only for display (sig16 << 16)
unsigned long pinSalt = 0;
uint16_t txNonce = 0;

// ------------------ TIME_LOCK ------------------
unsigned long lastLockBlinkMs = 0;
bool redBlink = false;
uint8_t lastShownSec = 255;

// ------------------ BUZZER ------------------
enum BeepPattern { BEEP_NONE, BEEP_SHORT, BEEP_DOUBLE, BEEP_ERROR, BEEP_LOCK, BEEP_TICK };
BeepPattern beepPattern = BEEP_NONE;

byte beepStep = 0;
unsigned long beepNextMs = 0;

// ------------------ PROTOTİPLER ------------------
char mapIRtoKey(unsigned long code);

void setState(State s);
void applyIndicatorsForState();
void allLedsOff();

void handleKey(char key);
void verifyPin();

void showMenu();
void lcdPrintMenuItem(byte idx);
void handleMenu(char key);

void handleTransaction(char key);

unsigned long generateSignature();
void showTransactionLCD();
void derivePinSalt();

// 2FA
void handle2FA(char key);
bool espVerifyTotp(const char* otp6);
void clearOtpEntry();

// LCD helpers
void lcdHeaderF(const __FlashStringHelper* title);
void lcdFooterClear();
void lcdMessageF(const __FlashStringHelper* l1, const __FlashStringHelper* l2, uint16_t d = 800);
void showLockCountdown(uint8_t secLeft);

// BUZZER helpers
void buzzerStart(BeepPattern p);
void buzzerUpdate();
void buzzerOffNow();
byte beepPriority(BeepPattern p);

// SD helpers
void sdInit();
bool sdEnsureHeader();
bool appendBlockToSD(const char* amount, uint16_t sig16, uint16_t nonce);
uint32_t fnv1a_update_u8(uint32_t h, uint8_t b);
uint32_t fnv1a_update_cstr(uint32_t h, const char* s);
uint32_t fnv1a_update_dec(uint32_t h, uint32_t v);
uint32_t fnv1a_update_hex(uint32_t h, uint32_t v);

// RAM-dostu restore
bool sdRestoreLastRecord_tail();

// Log clear
bool sdClearLog();

---

## C) Setup()

// ------------------ UTILS ------------------
static inline void clearPinEntry() {
  memset(enteredPin, 0, sizeof(enteredPin));
  pinIndex = 0;
}
static inline void clearAmountEntry() {
  memset(amountBuffer, 0, sizeof(amountBuffer));
  amountIndex = 0;
}
static inline void clearLastTxCache() {
  clearAmountEntry();
  fakeSignature = 0;
}

static inline bool isDigitC(char c) { return (c >= '0' && c <= '9'); }
static inline int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  return -1;
}
static uint32_t parseHex(const char* s) {
  uint32_t v = 0;
  while (*s) {
    int hv = hexVal(*s++);
    if (hv < 0) break;
    v = (v << 4) | (uint32_t)hv;
  }
  return v;
}
static uint32_t parseDec(const char* s) {
  uint32_t v = 0;
  while (*s && isDigitC(*s)) {
    v = v * 10 + (uint32_t)(*s - '0');
    s++;
  }
  return v;
}

void clearOtpEntry() {
  memset(enteredOtp, 0, sizeof(enteredOtp));
  otpIndex = 0;
}

// ------------------ SETUP ------------------
void setup() {
  IrReceiver.begin(IR_PIN, ENABLE_LED_FEEDBACK);

  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_YELLOW, OUTPUT);
  pinMode(LED_RED, OUTPUT);

  // UNO SPI master stabilitesi
  pinMode(10, OUTPUT);

  allLedsOff();
  buzzerOffNow();

  Wire.begin();
  lcd.init();
  lcd.backlight();

  // ESP UART
  espSerial.begin(9600);

  lcdMessageF(F("Donanim Cuzdan"), F("v1.0"), 600);
  lcdMessageF(F("Guvenli"), F("Baslatiliyor"), 450);

  derivePinSalt();
  sdInit();

  // Restore
  if (sdReady) {
    if (sdRestoreLastRecord_tail()) {
      lcdMessageF(F("SD Restore"), F("Son kayit OK"), 650);
    } else {
      lcdMessageF(F("SD Restore"), F("Kayit yok"), 650);
    }
  }

  setState(LOCKED);
  lcdHeaderF(F("PIN Giriniz"));
  lcdFooterClear();
}

---

## D) Main Loop & State Machine

// ------------------ LOOP ------------------
void loop() {
  buzzerUpdate();

  if (currentState == TIME_LOCK) {
    unsigned long now = millis();
    unsigned long elapsed = now - lockStartTime;
    long remainingMs = (long)LOCK_TIME - (long)elapsed;
    if (remainingMs < 0) remainingMs = 0;

    uint8_t secLeft = (uint8_t)((remainingMs + 999) / 1000);
    unsigned long interval = (secLeft <= LOCK_FAST_LAST_SEC) ? LOCK_BLINK_FAST_MS : LOCK_BLINK_NORMAL_MS;

    if (now - lastLockBlinkMs >= interval) {
      lastLockBlinkMs = now;
      redBlink = !redBlink;
      digitalWrite(LED_RED, redBlink ? HIGH : LOW);
      if (beepPattern == BEEP_NONE) buzzerStart(BEEP_TICK);
    }

    if (secLeft != lastShownSec) {
      lastShownSec = secLeft;
      showLockCountdown(secLeft);
    }

    if (elapsed >= LOCK_TIME) {
      attempts = 0;
      otpAttempts = 0;
      setState(LOCKED);
      lcdHeaderF(F("PIN Giriniz"));
      lcdFooterClear();
      clearPinEntry();
      clearOtpEntry();
      buzzerStart(BEEP_SHORT);
    }
    return;
  }

  if (IrReceiver.decode()) {
    unsigned long raw = IrReceiver.decodedIRData.decodedRawData;
    char key = mapIRtoKey(raw);

    if (key) {
      if (currentState == LOCKED) handleKey(key);
      else if (currentState == TWO_FA) handle2FA(key);
      else if (currentState == MENU) handleMenu(key);
      else if (currentState == TX_INPUT || currentState == TX_CONFIRM) handleTransaction(key);
      else if (currentState == LOG_CLEAR_CONFIRM) {
        // Log silme onayı
        if (key == 'O') {
          buzzerStart(BEEP_SHORT);
          lcdMessageF(F("Siliniyor"), F("..."), 250);

          bool ok = sdClearLog();

          if (ok) {
            lcdMessageF(F("Log Silindi"), F("Sifirlandi"), 650);
            buzzerStart(BEEP_DOUBLE);
          } else {
            lcdMessageF(F("SD Hata"), F("Silinemedi"), 700);
            buzzerStart(BEEP_ERROR);
          }

          setState(MENU);
          showMenu();
        } else if (key == 'X') {
          buzzerStart(BEEP_SHORT);
          setState(MENU);
          showMenu();
        }
      }
    }

    IrReceiver.resume();
  }
}

// ------------------ STATE ------------------
void setState(State s) { currentState = s; applyIndicatorsForState(); }

void applyIndicatorsForState() {
  allLedsOff();
  switch (currentState) {
    case LOCKED:            digitalWrite(LED_YELLOW, HIGH); break;
    case TWO_FA:            digitalWrite(LED_YELLOW, HIGH); break;
    case MENU:              digitalWrite(LED_GREEN, HIGH);  break;
    case TX_INPUT:
    case TX_CONFIRM:        digitalWrite(LED_YELLOW, HIGH); break;
    case LOG_CLEAR_CONFIRM: digitalWrite(LED_RED, HIGH);    break; // silme onayı kırmızı
    case TIME_LOCK:         digitalWrite(LED_RED, HIGH);    break;
  }
}

void allLedsOff() {
  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_YELLOW, LOW);
  digitalWrite(LED_RED, LOW);
}

---

## E) PIN Verification Logic

// ------------------ PIN ------------------
void handleKey(char key) {
  if (key >= '0' && key <= '9') {
    if (pinIndex < PIN_LENGTH) {
      enteredPin[pinIndex++] = key;
      lcd.setCursor(pinIndex - 1, 1);
      lcd.print('*');
      buzzerStart(BEEP_SHORT);
    }
    return;
  }

  if (key == 'C') { clearPinEntry(); lcdFooterClear(); buzzerStart(BEEP_SHORT); return; }

  if (key == 'O' && pinIndex == PIN_LENGTH) {
    enteredPin[PIN_LENGTH] = '\0';
    verifyPin();
    return;
  }

  if (key == 'X') { clearPinEntry(); lcdFooterClear(); buzzerStart(BEEP_SHORT); }
}

void verifyPin() {
  if (strcmp(enteredPin, correctPin) == 0) {
    lcdMessageF(F("PIN Dogru"), F("2FA Gerekli"), 450);
    buzzerStart(BEEP_DOUBLE);

    attempts = 0;
    viewingTx = false;

    // 2FA'ya geç
    setState(TWO_FA);
    clearOtpEntry();
    lcdHeaderF(F("2FA KOD GIR"));
    lcdFooterClear();
    buzzerStart(BEEP_SHORT);
  } else {
    attempts++;
    lcdMessageF(F("Yanlis PIN"), F("Tekrar Dene"), 450);
    buzzerStart(BEEP_ERROR);

    if (attempts >= MAX_ATTEMPTS) {
      lockStartTime = millis();
      lastLockBlinkMs = 0;
      redBlink = true;
      lastShownSec = 255;
      viewingTx = false;
      setState(TIME_LOCK);
      showLockCountdown(30);
      buzzerStart(BEEP_LOCK);
    } else {
      setState(LOCKED);
      lcdHeaderF(F("PIN Giriniz"));
      lcdFooterClear();
    }
  }
  clearPinEntry();
}

---

## F) SD Card Logging

// ------------------ ESP VERIFY ------------------
// UNO -> ESP: V123456\n
// ESP -> UNO: OK / NO
bool espVerifyTotp(const char* otp6) {
  while (espSerial.available()) espSerial.read(); // flush
  espSerial.print('V');
  espSerial.print(otp6);
  espSerial.print('\n');

  char resp[4] = {0};
  byte ri = 0;
  unsigned long t0 = millis();

  while (millis() - t0 < 1000) {
    if (espSerial.available()) {
      char c = (char)espSerial.read();
      if (c == '\n' || c == '\r') break;
      if (ri < 3) resp[ri++] = c;
    }
  }
  return (strcmp(resp, "OK") == 0);
}

void handle2FA(char key) {
  // rakam gir
  if (key >= '0' && key <= '9') {
    if (otpIndex < OTP_LEN) {
      enteredOtp[otpIndex++] = key;
      lcd.setCursor(otpIndex - 1, 1);
      lcd.print('*');
      buzzerStart(BEEP_SHORT);
    }
    return;
  }

  // temizle
  if (key == 'C') {
    clearOtpEntry();
    lcdFooterClear();
    buzzerStart(BEEP_SHORT);
    return;
  }

  // geri -> PIN ekranına dön
  if (key == 'X') {
    setState(LOCKED);
    lcdHeaderF(F("PIN Giriniz"));
    lcdFooterClear();
    clearPinEntry();
    clearOtpEntry();
    buzzerStart(BEEP_SHORT);
    return;
  }

  // OK -> doğrula
  if (key == 'O' && otpIndex == OTP_LEN) {
    enteredOtp[OTP_LEN] = '\0';

    lcdMessageF(F("2FA Kontrol"), F("..."), 220);

    if (espVerifyTotp(enteredOtp)) {
      lcdMessageF(F("2FA OK"), F("MENU Aciliyor"), 450);
      buzzerStart(BEEP_DOUBLE);

      otpAttempts = 0;
      setState(MENU);
      menuIndex = 0;
      showMenu();
    } else {
      otpAttempts++;
      lcdMessageF(F("2FA HATALI"), F("Tekrar Dene"), 450);
      buzzerStart(BEEP_ERROR);

      if (otpAttempts >= OTP_MAX_ATTEMPTS) {
        // Time lock
        lockStartTime = millis();
        lastLockBlinkMs = 0;
        redBlink = true;
        lastShownSec = 255;
        viewingTx = false;
        setState(TIME_LOCK);
        showLockCountdown(30);
        buzzerStart(BEEP_LOCK);
      } else {
        clearOtpEntry();
        lcdHeaderF(F("2FA KOD GIR"));
        lcdFooterClear();
      }
    }
  }
}

// ------------------ SD ------------------
void sdInit() {
  lcdMessageF(F("SD Kontrol"), F("Basliyor..."), 350);
  sdReady = SD.begin(SD_CS_PIN);

  if (sdReady) {
    sdEnsureHeader();
    lcdMessageF(F("SD Hazir"), F("Log aktif"), 450);
  } else {
    lcdMessageF(F("SD Yok/Ariza"), F("Log pasif"), 600);
  }
}

bool sdEnsureHeader() {
  if (!sdReady) return false;
  if (!SD.exists(SD_FILE_NAME)) {
    File f = SD.open(SD_FILE_NAME, FILE_WRITE);
    if (!f) return false;
    f.println(F("idx,ms,nonce,amount,sig16,prevHash,thisHash"));
    f.flush();
    f.close();
  }
  return true;
}

uint32_t fnv1a_update_u8(uint32_t h, uint8_t b) { h ^= b; h *= 16777619UL; return h; }
uint32_t fnv1a_update_cstr(uint32_t h, const char* s) { while (*s) h = fnv1a_update_u8(h, (uint8_t)(*s++)); return h; }
uint32_t fnv1a_update_dec(uint32_t h, uint32_t v) { char buf[11]; ultoa(v, buf, 10); return fnv1a_update_cstr(h, buf); }
uint32_t fnv1a_update_hex(uint32_t h, uint32_t v) { char buf[9]; ultoa(v, buf, 16); return fnv1a_update_cstr(h, buf); }

bool appendBlockToSD(const char* amount, uint16_t sig16, uint16_t nonce) {
  if (!sdReady) return false;
  if (!sdEnsureHeader()) return false;

  File f;
  for (uint8_t i = 0; i < 3; i++) {
    f = SD.open(SD_FILE_NAME, FILE_WRITE);
    if (f) break;
    delay(10);
  }
  if (!f) return false;

  uint32_t h = 2166136261UL;

  f.print(blockIndex);                 h = fnv1a_update_dec(h, blockIndex);  f.print(','); h = fnv1a_update_u8(h, ',');
  uint32_t ms = millis();
  f.print(ms);                         h = fnv1a_update_dec(h, ms);          f.print(','); h = fnv1a_update_u8(h, ',');
  f.print(nonce);                      h = fnv1a_update_dec(h, nonce);       f.print(','); h = fnv1a_update_u8(h, ',');
  f.print(amount);                     h = fnv1a_update_cstr(h, amount);     f.print(','); h = fnv1a_update_u8(h, ',');
  f.print(sig16, HEX);                 h = fnv1a_update_hex(h, sig16);       f.print(','); h = fnv1a_update_u8(h, ',');
  f.print(prevBlockHash, HEX);         h = fnv1a_update_hex(h, prevBlockHash); f.print(','); h = fnv1a_update_u8(h, ',');
  f.println(h, HEX);

  f.flush();
  f.close();

  prevBlockHash = h;
  blockIndex++;
  return true;
}

// Log dosyasını sil + header'ı yeniden oluştur + sayaçları sıfırla
bool sdClearLog() {
  if (!sdReady) return false;

  if (SD.exists(SD_FILE_NAME)) {
    if (!SD.remove(SD_FILE_NAME)) return false;
  }

  blockIndex = 0;
  prevBlockHash = 0;
  txNonce = 0;
  clearLastTxCache();

  return sdEnsureHeader();
}

// ------------------ RESTORE (tail) ------------------
bool sdRestoreLastRecord_tail() {
  if (!sdReady) return false;
  if (!SD.exists(SD_FILE_NAME)) return false;

  File f = SD.open(SD_FILE_NAME, FILE_READ);
  if (!f) return false;

  uint32_t sz = f.size();
  if (sz < 20) { f.close(); return false; }

  const uint8_t N = 80;
  char buf[N + 1];

  uint32_t start = (sz > N) ? (sz - N) : 0;
  f.seek(start);

  uint8_t i = 0;
  while (f.available() && i < N) buf[i++] = (char)f.read();
  buf[i] = '\0';
  f.close();

  int end = (int)i - 1;
  while (end >= 0 && (buf[end] == '\n' || buf[end] == '\r')) end--;
  if (end < 0) return false;

  int j = end;
  while (j >= 0 && buf[j] != '\n') j--;
  int lineStart = j + 1;

  if (lineStart + 7 <= (end + 1) && strncmp(&buf[lineStart], "idx,ms,", 7) == 0) return false;

  buf[end + 1] = '\0';
  char* line = &buf[lineStart];

  char* p = line;

  char* c1 = strchr(p, ','); if (!c1) return false; *c1 = 0;
  uint16_t idx = (uint16_t)parseDec(p);

  p = c1 + 1;
  char* c2 = strchr(p, ','); if (!c2) return false; *c2 = 0; // ms skip

  p = c2 + 1;
  char* c3 = strchr(p, ','); if (!c3) return false; *c3 = 0;
  uint16_t nonce = (uint16_t)parseDec(p);

  p = c3 + 1;
  char* c4 = strchr(p, ','); if (!c4) return false; *c4 = 0;
  strncpy(amountBuffer, p, sizeof(amountBuffer) - 1);
  amountBuffer[sizeof(amountBuffer) - 1] = '\0';
  amountIndex = strlen(amountBuffer);

  p = c4 + 1;
  char* c5 = strchr(p, ','); if (!c5) return false; *c5 = 0;
  uint16_t sig16 = (uint16_t)parseHex(p);

  p = c5 + 1;
  char* c6 = strchr(p, ','); if (!c6) return false; *c6 = 0; // prevHash skip

  p = c6 + 1;
  uint32_t thisH = parseHex(p);

  txNonce = nonce;
  fakeSignature = ((unsigned long)sig16) << 16;
  prevBlockHash = thisH;
  blockIndex = idx + 1;

  return true;
}


---

## G) LCD / UI Helpers

// ------------------ MENU ------------------
void lcdPrintMenuItem(byte idx) {
  char buf[17];
  strcpy_P(buf, (PGM_P)pgm_read_ptr(&menuItems[idx]));
  lcd.print(buf);
}

void showMenu() {
  lcdHeaderF(F("MENU"));
  lcd.setCursor(0, 1);
  lcd.print(F("                "));
  lcd.setCursor(0, 1);
  lcdPrintMenuItem(menuIndex);
}

void handleMenu(char key) {
  if (viewingTx) {
    if (key == 'X') { viewingTx = false; buzzerStart(BEEP_SHORT); showMenu(); }
    return;
  }

  if (key == 'U' && menuIndex > 0) { menuIndex--; buzzerStart(BEEP_SHORT); }
  if (key == 'D' && menuIndex < (MENU_COUNT - 1)) { menuIndex++; buzzerStart(BEEP_SHORT); }

  if (key == 'O') {
    if (menuIndex == 0) { showTransactionLCD(); return; }

    if (menuIndex == 1) {
      setState(TX_INPUT);
      clearAmountEntry();
      lcdHeaderF(F("Miktar Gir"));
      lcdFooterClear();
      buzzerStart(BEEP_SHORT);
      return;
    }

    if (menuIndex == 2) {
      setState(LOG_CLEAR_CONFIRM);
      lcdHeaderF(F("Log Sil?"));
      lcd.setCursor(0, 1);
      lcd.print(F("OK / X"));
      buzzerStart(BEEP_ERROR);
      return;
    }

    if (menuIndex == 3) {
      setState(LOCKED);
      viewingTx = false;
      otpAttempts = 0;
      clearOtpEntry();
      lcdMessageF(F("Cikis Yapildi"), F("PIN Giriniz"), 450);
      lcdHeaderF(F("PIN Giriniz"));
      lcdFooterClear();
      buzzerStart(BEEP_SHORT);
      return;
    }
  }

  showMenu();
}

---

## H) Other Helper Functions

// ------------------ TRANSACTION ------------------
void handleTransaction(char key) {
  if (currentState == TX_INPUT) {

    if (key >= '0' && key <= '9' && amountIndex < 5) {
      amountBuffer[amountIndex++] = key;
      lcd.setCursor(amountIndex - 1, 1);
      lcd.print(key);
      buzzerStart(BEEP_SHORT);
      return;
    }

    if (key == 'C') { clearAmountEntry(); lcdFooterClear(); buzzerStart(BEEP_SHORT); return; }

    if (key == 'O') {
      if (amountIndex == 0) {
        buzzerStart(BEEP_ERROR);
        lcdMessageF(F("Miktar Bos"), F("Giriniz"), 450);
        lcdHeaderF(F("Miktar Gir"));
        lcdFooterClear();
        return;
      }

      amountBuffer[amountIndex] = '\0';
      setState(TX_CONFIRM);
      lcdHeaderF(F("Islem Onay"));
      lcd.setCursor(0, 1);
      lcd.print(F("OK / X"));
      buzzerStart(BEEP_SHORT);
      return;
    }

    if (key == 'X') { setState(MENU); buzzerStart(BEEP_SHORT); showMenu(); return; }

  } else if (currentState == TX_CONFIRM) {

    if (key == 'O') {
      lcdMessageF(F("Imzalaniyor"), F("..."), 220);

      txNonce++;
      fakeSignature = generateSignature();
      uint16_t sig16 = (uint16_t)((fakeSignature >> 16) & 0xFFFF);

      bool ok = appendBlockToSD(amountBuffer, sig16, txNonce);

      if (ok) {
        lcdMessageF(F("Islem"), F("SD Kaydedildi"), 450);
        buzzerStart(BEEP_DOUBLE);
      } else {
        lcdMessageF(F("SD Hata"), F("Kayit Yok"), 520);
        buzzerStart(BEEP_ERROR);
      }

      setState(MENU);
      showMenu();
      return;
    }

    if (key == 'X') { setState(MENU); buzzerStart(BEEP_SHORT); showMenu(); return; }
  }
}

// ------------------ ISLEM GOSTER ------------------
void showTransactionLCD() {
  viewingTx = true;
  lcd.clear();

  if (fakeSignature == 0 || amountBuffer[0] == '\0') {
    lcd.print(F("Islem Yok"));
    lcd.setCursor(0, 1);
    lcd.print(F("Geri: X"));
    buzzerStart(BEEP_SHORT);
    return;
  }

  lcd.print(F("Miktar:"));
  lcd.print(amountBuffer);

  lcd.setCursor(0, 1);
  lcd.print(F("SIG:"));
  lcd.print((fakeSignature >> 16) & 0xFFFF, HEX);

  buzzerStart(BEEP_SHORT);
}

// ------------------ SIGNATURE ------------------
void derivePinSalt() {
  pinSalt = 0;
  for (byte i = 0; i < PIN_LENGTH; i++) {
    pinSalt = (pinSalt * 31UL) + (byte)correctPin[i];
  }
}

unsigned long generateSignature() {
  unsigned long hash = 2166136261UL;
  for (byte i = 0; i < amountIndex; i++) {
    hash ^= (byte)amountBuffer[i];
    hash *= 16777619UL;
  }
  hash ^= pinSalt;                 hash *= 16777619UL;
  hash ^= (unsigned long)txNonce;  hash *= 16777619UL;
  return hash;
}

// ------------------ LCD HELPERS ------------------
void lcdHeaderF(const __FlashStringHelper* title) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(title);
}

void lcdFooterClear() {
  lcd.setCursor(0, 1);
  lcd.print(F("                "));
}

void lcdMessageF(const __FlashStringHelper* l1, const __FlashStringHelper* l2, uint16_t d) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(l1);
  lcd.setCursor(0, 1);
  lcd.print(l2);
  delay(d);
}

void showLockCountdown(uint8_t secLeft) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(F("Kilitli!"));
  lcd.setCursor(0, 1);
  lcd.print(F("Kalan: "));
  if (secLeft < 10) lcd.print('0');
  lcd.print(secLeft);
  lcd.print(F(" sn"));
}

// ------------------ IR MAP ------------------
char mapIRtoKey(unsigned long code) {
  switch (code) {
    case 0xBA45FF00: return '1';
    case 0xB946FF00: return '2';
    case 0xB847FF00: return '3';
    case 0xBB44FF00: return '4';
    case 0xBF40FF00: return '5';
    case 0xBC43FF00: return '6';
    case 0xF807FF00: return '7';
    case 0xEA15FF00: return '8';
    case 0xF609FF00: return '9';
    case 0xE619FF00: return '0';

    case 0xE31CFF00: return 'O';
    case 0xF20DFF00: return 'X';
    case 0xE718FF00: return 'U';
    case 0xAD52FF00: return 'D';
    case 0xE916FF00: return 'C';

    default: return 0;
  }
}
