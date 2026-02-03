# Arduino Hardware Wallet Simulation

Arduino-based hardware wallet simulation with PIN, 2FA (TOTP), IR keypad input, and SD card logging.

## Features
- PIN verification with attempt limit and time-lock
- TOTP-based 2FA (ESP8266)
- IR remote input as a virtual keypad
- LCD + LED + buzzer feedback
- SD card transaction logging (block-like chained structure)
- State-machine based architecture

## Project Files
- `docs/` → Project report (PDF)
- `src/` → Source code files
- `assets/` → Images / media

## Source Code
- Arduino (main): `src/Arduino-Code.ino`
- ESP8266 (2FA): `src/ESP8266-Code.ino`

## Video
- Link: (https://www.youtube.com/watch?v=KcW8VPC15Lg)



