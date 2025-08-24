# SPACE DOA — CubeSat Blockchain Node
https://github.com/agreatopportunity/space_doa_esp32/tree/main

Raspberry Pi (Python) + ESP32 (C++) reference implementations

This repo contains two cooperating node implementations designed for tiny, power-constrained platforms (a Raspberry Pi “ground or flight” node and an ESP32 “flight” node). Both speak the same minimal UDP protocol (HELLO/ACK, INV/GETBLOCK, TX/BLOCK, PING/PONG), perform PoW, maintain a tiny UTXO set, and use authenticated encryption.

> The ESP32 firmware in this project is adapted from the “SPACE DOA – CubeSat Blockchain Controller, ESP32 Production-Ready Firmware v3.0.1” source.&#x20;

---

## Contents

* [Architecture Overview](#architecture-overview)
* [Protocol Overview](#protocol-overview)
* [Raspberry Pi Node (Python)](#raspberry-pi-node-python)
* [ESP32 Node (Arduino/C++)](#esp32-node-arduinoc)
* [End-to-End Bring-Up](#end-to-end-bring-up)
* [Operations & Maintenance](#operations--maintenance)
* [Troubleshooting](#troubleshooting)
* [Security Notes](#security-notes)
* [License](#license)

---

## Architecture Overview

* **Transport:** UDP on a local link (default port `8888`).
* **Clocking:** All packets include a wall-clock `ts` (seconds) and are accepted within a ±`RX_WINDOW_SEC` window to resist replay.
* **Rate limiting:** Token-bucket on send/recv to avoid flooding (`TOKEN_BUCKET_RATE`, `TOKEN_BUCKET_SIZE`).
* **Identity:** Long-term **P-256** identity key per device (compressed 33-byte public).
* **Session:** Ephemeral **ECDH P-256** → **HKDF-SHA256** → keys for **AES-256-GCM** (AEAD).
* **Nonce layout for AEAD:** `12 bytes = 4B session-prefix || 4B seq || 4B ts`.
* **Blockchain:** Minimal PoW (leading hex zeros), tiny mempool, UTXO tracking, JSON serialization, coinbase reward + fees.
* **Hardware hooks:** LEDs for status/TX/RX/error; I²C IMU example; SD or JSON file persistence depending on platform.

---

## Protocol Overview

### Wire header (13 bytes)

```
uint32 version
uint32 ts        # wall-clock seconds
uint32 seq       # monotonically increasing per-direction
uint8  type      # message type
```

### Message types

```
TX=1, BLOCK=2, PING=3, PONG=4, INV=5, GETBLOCK=6, HELLO=100, HELLO_ACK=101
```

### Handshake (plaintext), then AEAD

1. **HELLO** (plaintext JSON)

```json
{ "id": "<33B pub key hex>", "eph": "<33B eph key hex>", "na": "<12B nonce A hex>", "ts": 1712345678 }
```

2. **HELLO\_ACK** (plaintext JSON)

```json
{
  "id":"<responder 33B pub hex>",
  "eph":"<responder 33B eph hex>",
  "nb":"<12B nonce B hex>",
  "np":"<4B session nonce prefix hex>",
  "mac":"<HMAC-SHA256 transcript hex>",
  "ts":1712345680
}
```

3. **All subsequent packets are AES-GCM** with:

* AAD = 13-byte wire header
* Nonce = `np || seq || ts`
* Ciphertext = JSON body (e.g., TX/BLOCK/INV/GETBLOCK/PING/PONG)

### Chain sync mini-gossip

* **INV**: `{ "tip": <height>, "hash": "<tipHash64>" }`
* **GETBLOCK**: `{ "from": <startIndex>, "count": <1..8> }`
* **BLOCK**: serialized block (header + tx ids/tx bodies depending on side)

---

## Raspberry Pi Node (Python)

**File:** `spacedoa.py` (v3.0.1)
**Role:** Ground node or companion flight node.
**Runtime:** Python 3.9+ on Raspberry Pi OS.

### Features

* P-256 identity persisted as **encrypted PKCS#8 PEM** (`KEY_PASSWORD` in code).
* Ephemeral ECDH → HKDF → AES-GCM session.
* UDP server, token-bucket rate limiting, replay window.
* Mempool, PoW miner, UTXO rebuild, JSON on-disk chain (`blockchain.json`).
* GPIO LEDs for status/tx/rx/error; I²C IMU read (MPU-6050/9250).

### Prerequisites

```bash
sudo apt update
sudo apt install -y python3-pip python3-dev libffi-dev libssl-dev i2c-tools
pip3 install cryptography RPi.GPIO spidev smbus
# (Optionally) enable I2C: sudo raspi-config -> Interfaces -> I2C
```

### Configuration (edit in code)

```python
class Config:
    UDP_IP = "0.0.0.0"
    UDP_PORT = 8888
    ESP32_IP = "192.168.1.100"  # set peer IP
    PROTOCOL_VERSION = 1         # must match ESP32
    RX_WINDOW_SEC = 60
    TOKEN_BUCKET_RATE = 6
    TOKEN_BUCKET_SIZE = 30
    DIFFICULTY_LEADING_ZEROES = 4
    MAX_TX_PER_BLOCK = 10
    CHAIN_FILE = "blockchain.json"
    KEY_FILE = "node_key.pem"
    KEY_PASSWORD = b"space-doa-is-secure"
```

> ⚠️ Ensure `PROTOCOL_VERSION` matches the ESP32 build. In the sample ESP32 code it’s `2`—change one side so both match.

### Run

```bash
python3 spacedoa.py
```

You should see:

* `[CRYPTO] ...` key load or generation
* `[NET] UDP server listening on 0.0.0.0:8888`
* `[SESSION] established` after handshake
* `[SYSTEM] All threads started. Node is operational.`

### Optional: run as a service

`/etc/systemd/system/spacedoa.service`

```ini
[Unit]
Description=SPACE DOA Raspberry Pi Node
After=network-online.target

[Service]
User=pi
WorkingDirectory=/home/pi/spacedoa
ExecStart=/usr/bin/python3 spacedoa.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable spacedoa
sudo systemctl start spacedoa
sudo systemctl status spacedoa
```

---

## ESP32 Node (Arduino/C++)

**File:** `space_doa_micro.V3.1.c` (ESP32 firmware v3.0.1)
**Role:** Flight node (CubeSat/bench).
**Toolchains:** Arduino IDE or PlatformIO.

### Features

* P-256 identity stored in NVS; private key sealed at rest (AES-GCM under KEK derived from eFuse MAC via HKDF).
* Ephemeral P-256 ECDH → HKDF → AES-GCM session.
* UDP pump, token bucket, replay window, watchdog.
* Minimal blockchain: mempool, UTXO, PoW miner, SD-card backed chain & journal.
* LED indicators; I²C/SD stubs for typical CubeSat wiring.
* Peer allowlist (IP + compressed pubkey) hook.

> The constants, message types, networking, miner cadence, and persistence structure are visible in the firmware source.&#x20;

### Hardware pins (example)

```c
#define LED_STATUS 2
#define LED_TX     4
#define LED_RX     5
#define SD_CS      13
#define IMU_SDA    21
#define IMU_SCL    22
static const uint16_t UDP_PORT = 8888;
```

### Config (edit in source)

```c
static const char* WIFI_SSID = "CUBESAT_GROUND";
static const char* WIFI_PASS = "blockchain2024";
static const uint32_t PROTOCOL_VERSION = 2;  // MUST MATCH Pi node
static const uint32_t RX_WINDOW_SEC    = 60;
static const uint32_t TOKEN_RATE       = 6;
static const uint32_t TOKEN_BURST      = 30;
static const uint32_t POW_ZEROS        = 4;
```

**Peer allowlist**
Set the ground peer and its 33-byte compressed pubkey in `configurePeers()`:

```c++
static void configurePeers(){
  g_allowCount = 0;
  uint8_t groundPub[33] = { /* TODO: fill */ };
  g_allow[g_allowCount++] = { GROUND_HINT /* e.g., 192.168.4.1 */, {0} };
  memcpy(g_allow[0].pub, groundPub, 33);
}
```

### Build & Flash — Arduino IDE

1. Install **ESP32** board support (ESP32 by Espressif) in Boards Manager.
2. Open the `.c/.ino` source, select your board, set the correct COM port.
3. Install library dependency: **ArduinoJson** (and ensure standard ESP32 SDK/mbedTLS is available).
4. Flash.

### Build & Flash — PlatformIO

`platformio.ini` example:

```ini
[env:esp32]
platform = espressif32
board = esp32dev
framework = arduino
lib_deps = bblanchon/ArduinoJson
build_flags = -DCORE_DEBUG_LEVEL=1
monitor_speed = 115200
```

```bash
pio run
pio run -t upload
pio device monitor
```

### SD card (optional but recommended)

* FAT32-format an SD card; insert.
* Firmware writes an append-only `journal.log` and `chain/block_*.json` files (atomic temp+rename).

### Expected serial logs

* `[WiFi] connecting...` then IP
* `[UDP] listening on 8888`
* `[HELLO] sent` / `[HELLO_ACK] sent`
* `[SESSION] established`
* Mining ticks and block append logs.

---

## End-to-End Bring-Up

1. **Set IPs & versions**

   * On Pi: `Config.ESP32_IP` → ESP32’s IP (or AP gateway).
   * Align `PROTOCOL_VERSION` on both sides.

2. **Network**

   * Put ESP32 on a known SSID, or run it as STA to your lab AP.
   * Ensure Pi and ESP32 can route UDP/8888 (same L2 or routed).

3. **Keys**

   * ESP32 creates/seals identity in NVS on first boot.
   * Pi creates `node_key.pem` (encrypted with `KEY_PASSWORD`).

4. **Handshake**

   * Pi logs `[SESSION] established`.
   * ESP32 blinks and prints `[SESSION] established`.

5. **Blockchain**

   * Submit a few test TX (or let miner run).
   * Watch `blockchain.json` on Pi and `/chain/block_*.json` on SD.

---

## Operations & Maintenance

* **Mempool rebroadcast:** trickles up to `REB_TX_BURST` every `REBROADCAST_MS`.
* **Tip announcements:** `INV` every `INV_ANNOUNCE_MS`.
* **Mining cadence:** time-based (`MINE_INTERVAL_SEC`) or pressure (`MEMPOOL_MINE_MIN`).
* **UTXO state:** Pi rebuilds from chain on boot; ESP32 keeps compact arrays in RAM and persists blocks.
* **GPIO LEDs:**

  * STATUS: boot/mining ticks
  * TX/RX: short blinks on send/receive
  * ERROR (Pi): IMU read or other hardware faults

---

## Troubleshooting

* **MAC verify failed in HELLO\_ACK**

  * Mismatched `PROTOCOL_VERSION` or corrupted transcript fields.
  * Double-check both devices’ clocks (must be roughly in sync for RX window).

* \*\*`[RATE] drop (bucket)` / “Rate limit exceeded … Packet dropped.”

  * You hit the token bucket. Increase `TOKEN_*` or slow senders.

* **`Invalid authentication tag` / decrypt fail**

  * Out-of-order/replayed packet (seq/ts check), wrong nonce prefix, or key mismatch.
  * Ensure session is fully established before sending app messages.

* **No session establishment**

  * Wrong peer IP / Wi-Fi SSID/PASS (ESP32).
  * Firewalls blocking UDP/8888.
  * Allowlist on ESP32 not updated with the Pi’s pubkey.

* **Blocks not accepted**

  * PoW target too strict for the CPU; adjust `DIFFICULTY_LEADING_ZEROES`.
  * Merkle mismatch: confirm txids are computed deterministically and included.

---

## Security Notes

* **Key at rest:**

  * ESP32: identity sealed with AES-GCM under a KEK derived from **eFuse MAC via HKDF**.
  * Pi: identity stored as encrypted PKCS#8 (change `KEY_PASSWORD` before flight!).

* **Clock trust:** Replay window defenses depend on synchronized clocks.

* **Peer control:** The ESP32 has a built-in allowlist hook; use it in flight builds.

* **Production builds:** Rotate Wi-Fi creds into NVS/Secrets, remove debug logs, pin peer pubkeys, and consider enabling watchdogs aggressively.

---

## License

TBD by project owner. If unsure, consider MIT for code examples and documentation.

---

### Appendix — Useful Constants (quick reference)

| Constant           |         Pi |      ESP32 | Notes                  |
| ------------------ | ---------: | ---------: | ---------------------- |
| UDP Port           |       8888 |       8888 | Must match             |
| `PROTOCOL_VERSION` | 1 (sample) | 2 (sample) | Must match across both |
| RX window (s)      |         60 |         60 | Drop if outside        |
| Token rate/burst   |     6 / 30 |     6 / 30 | msgs/sec, bucket size  |
| PoW zeros          |          4 |          4 | Leading hex zeros      |
| Mine cadence       |       20 s |       20 s | Time-based             |
| Mempool pressure   |       3 tx |       3 tx | Early mine if ≥ N      |

If you want, I can tailor this README to your exact pinout, Wi-Fi mode (AP vs STA), and deployment topology (bench vs HIL vs flight).
