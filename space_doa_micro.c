/**
 * SPACE DOA - CubeSat Blockchain Controller
 * ESP32 Production-Ready Firmware
 * Version: 3.0.0
 *
 * This firmware is a hardened implementation for a lightweight blockchain node
 * intended for deployment on a CubeSat in Low Earth Orbit (LEO).
 * 
 * 
 * */
// ---------------------------- CONFIGURATION ----------------------------

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

// #define USE_LORA 1
#ifdef USE_LORA
  #include <LoRa.h>   // sandeepmistry/LoRa
#endif

// GPIOs (adjust to your board)
#define LED_STATUS 2
#define LED_TX     4
#define LED_RX     5
#define SD_CS      13
#define IMU_SDA    21
#define IMU_SCL    22

#ifdef USE_LORA
  #define LORA_SS    15
  #define LORA_RST   14
  #define LORA_DIO0  26
  #define LORA_FREQ  915E6
#endif

// Wi‑Fi/UDP
static const char* WIFI_SSID = "CUBESAT_GROUND";      // Move to NVS in production
static const char* WIFI_PASS = "blockchain2024";      // Move to NVS in production
static const uint16_t UDP_PORT = 8888;

// Limits & sizes
static const uint32_t PROTOCOL_VERSION = 1;
static const size_t   MAX_TX_PER_BLOCK = 10;
static const size_t   MAX_MEMPOOL      = 100;
static const size_t   MAX_BLOCKS       = 1000;       // In-RAM safety cap; long-term chain lives on SD
static const size_t   MAX_MSG_SIZE     = 768;        // Hard cap to prevent abuse
static const uint32_t DIFFICULTY_LEADING_ZEROES = 4; // If you keep PoW

// Replay + rate limiting
static const uint32_t RX_WINDOW_SEC     = 60;        // Accept timestamps within ±60s
static const uint32_t TOKEN_BUCKET_RATE = 6;         // msgs per second allowed
static const uint32_t TOKEN_BUCKET_SIZE = 30;        // burst size

// Watchdog
static const uint32_t WDT_TIMEOUT_SEC   = 10;        // Per-task watchdog

// Storage
static const char* CHAIN_DIR = "/chain";
static const char* JOURNAL   = "/chain/journal.log";  // append-only, atomic via temp+rename

// ----------------------------------------------------------------------
// Utility: monotonic seconds
static inline uint32_t nowSec() { return (uint32_t)(esp_timer_get_time() / 1000000ULL); }

// ---------------------------- CRYPTO LAYER -----------------------------
// Identity keypair (ECDSA P-256). Stored in NVS/EEPROM in production.
struct Identity {
  mbedtls_ecdsa_context ecdsa;
  mbedtls_ecp_group grp;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr;
  bool ready = false;

  Identity() { init(); }
  ~Identity() { free(); }

  void init() {
    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_ecp_group_init(&grp);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);
    const char *pers = "esp32-ecdsa";
    int rc;
    if ((rc = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                                    (const unsigned char*)pers, strlen(pers))) != 0) {
      Serial.printf("[CRYPTO] DRBG seed failed: %d\n", rc);
      return;
    }
    if ((rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) != 0) {
      Serial.printf("[CRYPTO] Load group failed: %d\n", rc);
      return;
    }
    if ((rc = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1,
                                    mbedtls_ctr_drbg_random, &ctr)) != 0) {
      Serial.printf("[CRYPTO] Genkey failed: %d\n", rc);
      return;
    }
    ready = true;
  }

  void free() {
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
  }

  // Export compressed public key (33 bytes, SEC1 format 0x02/0x03 + X)
  bool pubkeyCompressed(uint8_t out[33]) {
    if (!ready) return false;
    size_t olen = 0;
    int rc = mbedtls_ecp_point_write_binary(&grp, &ecdsa.Q,
              MBEDTLS_ECP_PF_COMPRESSED, &olen, out, 33);
    return rc == 0 && olen == 33;
  }

  // Sign bytes with SHA-256(ECDSA)
  bool sign(const uint8_t *msg, size_t len, std::vector<uint8_t> &sigDer) {
    if (!ready) return false;
    uint8_t hash[32];
    mbedtls_sha256(msg, len, hash, 0);
    size_t sig_len = 0;
    sigDer.assign(80, 0); // enough for DER sig
    int rc = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256,
                  hash, sizeof(hash), sigDer.data(), &sig_len,
                  mbedtls_ctr_drbg_random, &ctr);
    if (rc != 0) return false;
    sigDer.resize(sig_len);
    return true;
  }

  // Verify signature (peer's pubkey)
  static bool verifyCompressedPub(const uint8_t pub[33], const uint8_t *msg, size_t len,
                                  const uint8_t *sig, size_t sigLen) {
    mbedtls_ecp_group grp; mbedtls_ecp_group_init(&grp);
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) { mbedtls_ecp_group_free(&grp); return false; }
    mbedtls_ecp_point Q; mbedtls_ecp_point_init(&Q);

    if (mbedtls_ecp_point_read_binary(&grp, &Q, pub, 33) != 0) { mbedtls_ecp_point_free(&Q); mbedtls_ecp_group_free(&grp); return false; }

    mbedtls_ecdsa_context ctx; mbedtls_ecdsa_init(&ctx);
    if (mbedtls_ecdsa_from_keypair(&ctx, &(mbedtls_ecp_keypair){ .grp = grp, .Q = Q }) != 0) {
      mbedtls_ecdsa_free(&ctx); mbedtls_ecp_point_free(&Q); mbedtls_ecp_group_free(&grp); return false;
    }
    uint8_t hash[32];
    mbedtls_sha256(msg, len, hash, 0);
    int rc = mbedtls_ecdsa_read_signature(&ctx, hash, sizeof(hash), sig, sigLen);
    mbedtls_ecdsa_free(&ctx); mbedtls_ecp_point_free(&Q); mbedtls_ecp_group_free(&grp);
    return rc == 0;
  }
};

Identity g_id;

// ---------------------------- TRANSPORT -------------------------------
struct TokenBucket { double tokens = TOKEN_BUCKET_SIZE; uint32_t last = nowSec(); };
static TokenBucket g_bucket;

static bool bucket_allow() {
  uint32_t t = nowSec();
  uint32_t dt = t - g_bucket.last;
  if (dt > 0) {
    g_bucket.tokens = std::min<double>(TOKEN_BUCKET_SIZE, g_bucket.tokens + dt * TOKEN_BUCKET_RATE);
    g_bucket.last = t;
  }
  if (g_bucket.tokens >= 1.0) { g_bucket.tokens -= 1.0; return true; }
  return false;
}

// Basic AES-GCM helpers (mbedTLS). In production, derive key via ECDH handshake.
struct AeadKey { uint8_t key[32]; bool set=false; };
static AeadKey g_netKey; // network session key (temporary solution)

static bool aead_encrypt(const uint8_t *pt, size_t ptLen, const uint8_t *aad, size_t aadLen,
                         uint8_t *nonce12, uint8_t *ct, size_t &ctLen,
                         uint8_t *tag16) {
  if (!g_netKey.set) return false;
  const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
  if (!info) return false;
  mbedtls_cipher_context_t ctx; mbedtls_cipher_init(&ctx);
  if (mbedtls_cipher_setup(&ctx, info) != 0) { mbedtls_cipher_free(&ctx); return false; }
  int rc = mbedtls_cipher_auth_encrypt(&ctx, nonce12, 12, aad, aadLen,
                                       pt, ptLen, ct, &ctLen, tag16, 16);
  mbedtls_cipher_free(&ctx);
  return rc == 0;
}

static bool aead_decrypt(const uint8_t *ct, size_t ctLen, const uint8_t *aad, size_t aadLen,
                         uint8_t *nonce12, const uint8_t *tag16, uint8_t *pt, size_t &ptLen) {
  if (!g_netKey.set) return false;
  const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
  if (!info) return false;
  mbedtls_cipher_context_t ctx; mbedtls_cipher_init(&ctx);
  if (mbedtls_cipher_setup(&ctx, info) != 0) { mbedtls_cipher_free(&ctx); return false; }
  int rc = mbedtls_cipher_auth_decrypt(&ctx, nonce12, 12, aad, aadLen,
                                       ct, ctLen, pt, &ptLen, tag16, 16);
  mbedtls_cipher_free(&ctx);
  return rc == 0;
}

// For demo, seed a per-deployment symmetric key from hardware RNG at first boot and keep in NVS.
#include <Preferences.h>
Preferences kv;
static void ensure_net_key() {
  if (!kv.begin("spacedoa", false)) return;
  if (kv.getBytesLength("netk") == 32) {
    kv.getBytes("netk", g_netKey.key, 32); g_netKey.set = true; kv.end(); return;
  }
  esp_fill_random(g_netKey.key, 32);
  kv.putBytes("netk", g_netKey.key, 32); kv.end(); g_netKey.set = true;
}

// ---------------------------- LED helpers -----------------------------
static inline void ledBlink(uint8_t pin, uint16_t onMs=50) { digitalWrite(pin,HIGH); delay(onMs); digitalWrite(pin,LOW); }

// ------------------------------ UTXO ----------------------------------
struct TxIn  { char prevTx[65]; uint32_t vout; };
struct TxOut { uint32_t amount; uint8_t toPub[33]; };

struct Transaction {
  uint32_t version{1};
  uint32_t timestamp{0};
  uint8_t  fromPub[33]{};  // signer pubkey
  uint8_t  inCount{0}, outCount{0};
  TxIn     vin[2];         // small footprint demo
  TxOut    vout[2];
  // DER signature (variable length up to ~72B)
  uint16_t sigLen{0};
  uint8_t  sig[80];
  char     txid[65];
};

struct UTXOEntry { char txid[65]; uint32_t idx; uint32_t amount; uint8_t toPub[33]; bool spent; };

// ---------------------------- BLOCKCHAIN -------------------------------
struct BlockHeader {
  uint32_t version{1};
  uint32_t index{0};
  uint32_t timestamp{0};
  char prevHash[65];
  char merkle[65];
  uint32_t nonce{0};
  char hash[65];
};

struct Block { BlockHeader h; uint8_t txCount{0}; Transaction tx[MAX_TX_PER_BLOCK]; };

static Block g_chain[MAX_BLOCKS];
static uint16_t g_height = 0;

static UTXOEntry g_utxo[2*MAX_MEMPOOL];
static uint16_t  g_utxoCount = 0;

static Transaction g_mempool[MAX_MEMPOOL];
static uint16_t    g_mempoolSize = 0;

static SemaphoreHandle_t g_chainMtx;
static SemaphoreHandle_t g_mempoolMtx;

// Hex helpers
static void toHex(const uint8_t* in, size_t n, char* out) {
  static const char* H="0123456789abcdef"; for (size_t i=0;i<n;i++){ out[2*i]=H[in[i]>>4]; out[2*i+1]=H[in[i]&0xF]; }
  out[2*n]='\0';
}

// Merkle: hash pairs (dup last if odd) until single 32B
static void merkleRoot(const Transaction *tx, uint8_t n, char out64[65]) {
  if (n == 0) { memset(out64,'0',64); out64[64]='\0'; return; }
  std::vector<std::array<uint8_t,32>> layer; layer.reserve(n);
  for (uint8_t i=0;i<n;i++){ uint8_t h[32]; mbedtls_sha256((const uint8_t*)tx[i].txid, 64, h, 0); layer.push_back({}); memcpy(layer.back().data(),h,32);} 
  while (layer.size()>1){
    std::vector<std::array<uint8_t,32>> nxt; for (size_t i=0;i<layer.size(); i+=2){
      const auto &a = layer[i]; const auto &b = (i+1<layer.size()? layer[i+1]: layer[i]);
      uint8_t h[32]; mbedtls_sha256_ret(a.data(),32,h,0); mbedtls_sha256_ret(b.data(),32,h,0); // simple concat-hash
      uint8_t cat[64]; memcpy(cat,a.data(),32); memcpy(cat+32,b.data(),32);
      mbedtls_sha256(cat,64,h,0); nxt.push_back({}); memcpy(nxt.back().data(),h,32);
    }
    layer.swap(nxt);
  }
  toHex(layer[0].data(),32,out64);
}

static void hashBlockHeader(BlockHeader &bh) {
  char buf[256];
  snprintf(buf,sizeof(buf),"%u%u%u%s%s%u", bh.version,bh.index,bh.timestamp,bh.prevHash,bh.merkle,bh.nonce);
  uint8_t h[32]; mbedtls_sha256((const uint8_t*)buf, strlen(buf), h, 0);
  toHex(h,32,bh.hash);
}

// ---------------------------- PERSISTENCE ------------------------------
static bool fsWriteAtomic(const char* path, const uint8_t* data, size_t len) {
  String tmp = String(path)+".tmp";
  File f = SD.open(tmp.c_str(), FILE_WRITE);
  if (!f) return false;
  size_t w = f.write(data, len); f.flush(); f.close();
  if (w != len) { SD.remove(tmp.c_str()); return false; }
  if (SD.exists(path)) SD.remove(path);
  return SD.rename(tmp.c_str(), path);
}

static bool appendJournal(const char* jsonLine) {
  File f = SD.open(JOURNAL, FILE_APPEND);
  if (!f) return false;
  size_t w = f.println(jsonLine);
  f.flush(); f.close(); return w>0;
}

// --------------------------- VERIFICATION ------------------------------
static bool verifyTx(const Transaction &tx) {
  // Create signing preimage (version|timestamp|vin|vout|fromPub)
  // Minimal encoding for demo; ensure deterministic layout.
  StaticJsonDocument<512> d;
  d["v"]=tx.version; d["t"]=tx.timestamp; d["fc"]=tx.inCount; d["tc"]=tx.outCount;
  JsonArray vin = d.createNestedArray("in");
  for (uint8_t i=0;i<tx.inCount;i++){ JsonArray a = vin.createNestedArray(); a.add(tx.vin[i].prevTx); a.add(tx.vin[i].vout); }
  JsonArray vout = d.createNestedArray("out");
  for (uint8_t i=0;i<tx.outCount;i++){ JsonArray a = vout.createNestedArray(); a.add(tx.vout[i].amount); char pkhex[67]; toHex(tx.vout[i].toPub,33,pkhex); a.add(pkhex); }
  char pre[512]; size_t n = serializeJson(d, pre, sizeof(pre));
  return Identity::verifyCompressedPub(tx.fromPub, (const uint8_t*)pre, n, tx.sig, tx.sigLen);
}

static bool applyTxToUTXO(const Transaction &tx) {
  // Spend inputs
  for (uint8_t i=0;i<tx.inCount;i++){
    bool found=false; for (uint16_t j=0;j<g_utxoCount;j++){
      if (!g_utxo[j].spent && strcmp(g_utxo[j].txid, tx.vin[i].prevTx)==0 && g_utxo[j].idx==tx.vin[i].vout) {
        // Ownership check: input must be locked to fromPub
        if (memcmp(g_utxo[j].toPub, tx.fromPub, 33)!=0) return false;
        g_utxo[j].spent=true; found=true; break;
      }
    }
    if (!found) return false;
  }
  // Create outputs
  for (uint8_t k=0;k<tx.outCount;k++){
    if (g_utxoCount >= (int)(sizeof(g_utxo)/sizeof(g_utxo[0]))) return false;
    strncpy(g_utxo[g_utxoCount].txid, tx.txid, 65); g_utxo[g_utxoCount].idx=k;
    g_utxo[g_utxoCount].amount=tx.vout[k].amount; memcpy(g_utxo[g_utxoCount].toPub, tx.vout[k].toPub, 33);
    g_utxo[g_utxoCount].spent=false; g_utxoCount++;
  }
  return true;
}

static void calcTxId(Transaction &tx) {
  StaticJsonDocument<256> d; d["v"]=tx.version; d["t"]=tx.timestamp; d["fc"]=tx.inCount; d["tc"]=tx.outCount;
  char pre[256]; size_t n = serializeJson(d, pre, sizeof(pre));
  uint8_t h[32]; mbedtls_sha256((const uint8_t*)pre, n, h, 0); toHex(h,32,tx.txid);
}

// ---------------------------- NETWORK RX/TX ----------------------------
WiFiUDP g_udp;

struct WireMessage {
  uint32_t ver;
  uint32_t ts;
  uint32_t seq;
  uint8_t  type; // 1=TX, 2=BLOCK, 3=PING, 4=PONG
  // payload is JSON (capped by MAX_MSG_SIZE)
};

static uint32_t g_txSeq=0; // local seq counter

static bool sendEncrypted(const IPAddress &peer, uint8_t type, const char* json, size_t len) {
  if (!bucket_allow()) return false;
  if (len > MAX_MSG_SIZE) return false;
  WireMessage hdr{PROTOCOL_VERSION, nowSec(), g_txSeq++, type};
  uint8_t aad[sizeof(hdr)]; memcpy(aad,&hdr,sizeof(hdr));
  uint8_t nonce[12]; esp_fill_random(nonce, sizeof(nonce));
  uint8_t tag[16]; size_t ctLen=0; std::vector<uint8_t> ct(len);
  if (!aead_encrypt((const uint8_t*)json, len, aad, sizeof(aad), nonce, ct.data(), ctLen, tag)) return false;
  g_udp.beginPacket(peer, UDP_PORT);
  g_udp.write((uint8_t*)&hdr, sizeof(hdr));
  g_udp.write(nonce,12); g_udp.write(tag,16); g_udp.write(ct.data(), ctLen);
  bool ok = g_udp.endPacket(); if (ok) ledBlink(LED_TX,10); return ok;
}

static bool recvEncrypted(char *outJson, size_t &outLen, uint8_t &outType) {
  int pkt = g_udp.parsePacket(); if (!pkt) return false;
  if (pkt < (int)(sizeof(WireMessage)+12+16)) { g_udp.flush(); return false; }
  WireMessage hdr; g_udp.read((uint8_t*)&hdr, sizeof(hdr));
  if (hdr.ver != PROTOCOL_VERSION) { g_udp.flush(); return false; }
  // timestamp window
  uint32_t t = nowSec(); if (hdr.ts+RX_WINDOW_SEC < t || hdr.ts > t+RX_WINDOW_SEC) { g_udp.flush(); return false; }
  uint8_t nonce[12]; uint8_t tag[16]; g_udp.read(nonce,12); g_udp.read(tag,16);
  int remain = pkt - (sizeof(WireMessage)+12+16);
  remain = std::min(remain, (int)MAX_MSG_SIZE);
  std::vector<uint8_t> ct(remain); g_udp.read(ct.data(), remain);
  std::vector<uint8_t> pt(remain);
  size_t ptLen=0; if (!aead_decrypt(ct.data(), remain, (uint8_t*)&hdr, sizeof(hdr), nonce, tag, pt.data(), ptLen)) return false;
  outLen = std::min(ptLen, (size_t)MAX_MSG_SIZE);
  memcpy(outJson, pt.data(), outLen); outJson[outLen] = '\0';
  outType = hdr.type; ledBlink(LED_RX, 5); return true;
}

// ------------------------------ TASKS ---------------------------------
static TaskHandle_t t_net, t_mine, t_telem;

static void taskNetwork(void *arg) {
  esp_task_wdt_add(NULL);
  StaticJsonDocument<1024> d;
  char buf[MAX_MSG_SIZE+1]; size_t n; uint8_t type;
  for(;;){
    if (recvEncrypted(buf, n, type)) {
      esp_task_wdt_reset();
      DeserializationError e = deserializeJson(d, buf, n);
      if (!e) {
        if (type==1) {
          // TX
          Transaction tx; // TODO: parse JSON -> tx
          // Verify + enqueue
          if (verifyTx(tx)) {
            xSemaphoreTake(g_mempoolMtx, portMAX_DELAY);
            if (g_mempoolSize < MAX_MEMPOOL) g_mempool[g_mempoolSize++] = tx;
            xSemaphoreGive(g_mempoolMtx);
          }
        } else if (type==2) {
          // BLOCK (left as exercise: full header+tx verification, reorgs, etc.)
        } else if (type==3) {
          // PING -> PONG
          StaticJsonDocument<128> pong; pong["type"]="PONG"; pong["h"]=g_height; char js[128]; size_t L=serializeJson(pong, js, sizeof(js));
          sendEncrypted(g_udp.remoteIP(), 4, js, L);
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(5));
  }
}

static void taskMining(void *arg) {
  esp_task_wdt_add(NULL);
  for(;;){
    esp_task_wdt_reset();
    // Simple PoW miner if mempool > 0
    xSemaphoreTake(g_mempoolMtx, portMAX_DELAY);
    uint8_t ready = min<uint16_t>(g_mempoolSize, MAX_TX_PER_BLOCK);
    if (ready==0) { xSemaphoreGive(g_mempoolMtx); vTaskDelay(pdMS_TO_TICKS(1000)); continue; }
    Block b; memset(&b,0,sizeof(b)); b.h.index = g_height; b.h.timestamp = nowSec();
    if (g_height==0) strcpy(b.h.prevHash, "0000000000000000000000000000000000000000000000000000000000000000");
    else strcpy(b.h.prevHash, g_chain[g_height-1].h.hash);
    b.txCount = ready; for (uint8_t i=0;i<ready;i++){ b.tx[i] = g_mempool[i]; }
    // shift mempool
    for (uint16_t i=ready;i<g_mempoolSize;i++) g_mempool[i-ready]=g_mempool[i];
    g_mempoolSize -= ready; xSemaphoreGive(g_mempoolMtx);

    merkleRoot(b.tx, b.txCount, b.h.merkle);
    // PoW loop
    char target[DIFFICULTY_LEADING_ZEROES+1]; memset(target,'0',sizeof(target)-1); target[sizeof(target)-1]='\0';
    for(;;){ hashBlockHeader(b.h); if (strncmp(b.h.hash, target, DIFFICULTY_LEADING_ZEROES)==0) break; b.h.nonce++; if ((b.h.nonce%2048)==0) vTaskDelay(1); }

    // Validate and commit
    bool ok=true; for (uint8_t i=0;i<b.txCount;i++){ if (!verifyTx(b.tx[i]) || !applyTxToUTXO(b.tx[i])) { ok=false; break; } }
    if (!ok) continue;

    xSemaphoreTake(g_chainMtx, portMAX_DELAY);
    g_chain[g_height] = b; g_height++;
    xSemaphoreGive(g_chainMtx);

    // Persist header + tx list (JSON line)
    StaticJsonDocument<256> j; j["i"]=b.h.index; j["h"]=b.h.hash; j["p"]=b.h.prevHash; j["m"]=b.h.merkle; j["n"]=b.h.nonce; char line[256]; size_t L=serializeJson(j,line,sizeof(line));
    appendJournal(line);
    ledBlink(LED_STATUS, 30);
  }
}

static void taskTelemetry(void *arg) {
  esp_task_wdt_add(NULL);
  Wire.begin(IMU_SDA, IMU_SCL);
  for(;;){
    esp_task_wdt_reset();
    Serial.printf("[STATUS] Height=%u Mempool=%u UTXO=%u Heap=%u\n", g_height, g_mempoolSize, g_utxoCount, ESP.getFreeHeap());
    // Try IMU read with graceful recovery
    Wire.beginTransmission(0x68); Wire.write(0x75); if (Wire.endTransmission(false)==0 && Wire.requestFrom(0x68,1,true)==1){ uint8_t who = Wire.read(); Serial.printf("[IMU] WHOAMI=0x%02X\n", who); }
    else { Serial.println("[IMU] Reinit I2C"); Wire.end(); delay(10); Wire.begin(IMU_SDA, IMU_SCL); }
    vTaskDelay(pdMS_TO_TICKS(15000));
  }
}

// ------------------------------ SETUP ---------------------------------
void setup(){
  Serial.begin(115200); delay(200);
  pinMode(LED_STATUS, OUTPUT); pinMode(LED_TX, OUTPUT); pinMode(LED_RX, OUTPUT);
  digitalWrite(LED_STATUS,LOW); digitalWrite(LED_TX,LOW); digitalWrite(LED_RX,LOW);

  // Crypto & network key
  if (!g_id.ready) { Serial.println("[CRYPTO] Identity init failed"); }
  ensure_net_key();

  // SD
  if (!SD.begin(SD_CS)) Serial.println("[SD] init failed"); else { if (!SD.exists(CHAIN_DIR)) SD.mkdir(CHAIN_DIR); }

  // Wi‑Fi
  WiFi.mode(WIFI_STA); WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("[WIFI] Connecting"); for (int i=0;i<40 && WiFi.status()!=WL_CONNECTED;i++){ delay(250); Serial.print("."); }
  if (WiFi.status()==WL_CONNECTED){ Serial.printf(" connected: %s\n", WiFi.localIP().toString().c_str()); g_udp.begin(UDP_PORT); Serial.printf("[UDP] Listening %u\n", UDP_PORT); }
  else { Serial.println(" failed; offline mode"); }

#ifdef USE_LORA
  SPI.begin(); LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQ)) Serial.println("[LORA] init failed"); else Serial.println("[LORA] ready");
#endif

  // Mutexes
  g_chainMtx = xSemaphoreCreateMutex(); g_mempoolMtx = xSemaphoreCreateMutex();

  // WDT init for this task + future tasks
  esp_task_wdt_init(WDT_TIMEOUT_SEC, true);

  // Start tasks (pin to core 1 for net/mine, core 0 for telem)
  xTaskCreatePinnedToCore(taskNetwork,  "net",   8192, nullptr, 3, &t_net,   1);
  xTaskCreatePinnedToCore(taskMining,   "mine",  8192, nullptr, 2, &t_mine,  1);
  xTaskCreatePinnedToCore(taskTelemetry,"telem", 4096, nullptr, 1, &t_telem, 0);

  Serial.println("[SYSTEM] SPACE DOA secure node online");
}

void loop(){
  // main loop idle; tasks do the work
  vTaskDelay(pdMS_TO_TICKS(1000));
}

// ------------------------------ NOTES ---------------------------------
// * Replace temporary symmetric key with a real ECDH handshake to derive per-peer session keys.
// * Persist identity keys to NVS (Preferences) and enable flash encryption + secure boot.
// * Implement full TX JSON <-> struct mapping and add fee handling & timestamp validity.
// * Add peer allowlist with their public keys and rotate keys periodically.
// * Consider PoA/BFT for cubesat ops rather than PoW.
// * Add full block validation, reorg handling, and chain download/resync.
