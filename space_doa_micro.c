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
#include <ArduinoJson.h>
#include <Preferences.h>

#include <vector>
#include <array>
#include <algorithm>
#include <cstring>

#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/gcm.h>

// ---------------------------- CONFIG ----------------------------------
// GPIOs (adjust to board)
#define LED_STATUS 2
#define LED_TX     4
#define LED_RX     5
#define SD_CS      13
#define IMU_SDA    21
#define IMU_SCL    22

// Wi-Fi/UDP
static const char* WIFI_SSID = "CUBESAT_GROUND";   // move to NVS in deployment
static const char* WIFI_PASS = "blockchain2024";   // move to NVS in deployment
static const uint16_t UDP_PORT = 8888;

// Ground station peer hint (optional for faster connect)
static const IPAddress GROUND_HINT(192,168,4,1);

// Protocol
static const uint32_t PROTOCOL_VERSION = 2;
static const size_t   MAX_MSG_SIZE     = 768;
static const uint32_t RX_WINDOW_SEC    = 60;    // timestamp accept window
static const uint32_t TOKEN_RATE       = 6;     // msgs/sec
static const uint32_t TOKEN_BURST      = 30;    // bucket size
static const uint32_t WDT_TIMEOUT_SEC  = 10;    // per-task watchdog
static const uint32_t HANDSHAKE_TIMEOUT_MS = 5000;

// Chain sizes
static const size_t   MAX_TX_PER_BLOCK = 10;
static const size_t   MAX_MEMPOOL      = 100;
static const size_t   MAX_BLOCKS       = 1000;
static const uint32_t POW_ZEROS        = 4;     // leading hex zeros

// Fee & policy
static const uint32_t MIN_FEE_PER_TX   = 1;     // smallest unit
static const uint32_t TX_FRESH_WINDOW  = 60;    // seconds

// Storage
static const char* CHAIN_DIR = "/chain";
static const char* JOURNAL   = "/chain/journal.log"; // append-only log (atomic via temp+rename)

// Misc
static inline uint32_t nowSec(){ return (uint32_t)(esp_timer_get_time()/1000000ULL); }
static inline void ledBlink(uint8_t pin, uint16_t onMs=30){ digitalWrite(pin,HIGH); delay(onMs); digitalWrite(pin,LOW); }

// Hex helpers
static void toHex(const uint8_t* in, size_t n, char* out){
  static const char* H="0123456789abcdef";
  for(size_t i=0;i<n;i++){ out[2*i]=H[in[i]>>4]; out[2*i+1]=H[in[i]&0xF]; }
  out[2*n]='\0';
}
static bool fromHex(const char* hx, uint8_t* out, size_t outlen){
  if(!hx) return false; size_t L=strlen(hx); if(L!=outlen*2) return false;
  auto nyb=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
  for(size_t i=0;i<outlen;i++){ int a=nyb(hx[2*i]), b=nyb(hx[2*i+1]); if(a<0||b<0) return false; out[i]=(uint8_t)((a<<4)|b); }
  return true;
}

// --------------------------- TOKEN BUCKET ------------------------------
struct TokenBucket { double tokens=TOKEN_BURST; uint32_t last=nowSec(); };
static TokenBucket g_bucket;

static bool bucket_allow(){
  uint32_t t=nowSec(); uint32_t dt=t-g_bucket.last;
  if(dt>0){ g_bucket.tokens=std::min<double>(TOKEN_BURST, g_bucket.tokens+dt*TOKEN_RATE); g_bucket.last=t; }
  if(g_bucket.tokens>=1.0){ g_bucket.tokens-=1.0; return true; } return false;
}

// ---------------------------- CRYPTO CORE ------------------------------
// AES-256-GCM using mbedTLS GCM API
static bool aes_gcm_encrypt(const uint8_t key[32], const uint8_t *pt, size_t ptLen,
                            const uint8_t *aad, size_t aadLen,
                            const uint8_t nonce[12], uint8_t *ct,
                            uint8_t tag[16]){
  mbedtls_gcm_context ctx; mbedtls_gcm_init(&ctx);
  if(mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256)!=0){ mbedtls_gcm_free(&ctx); return false; }
  int rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, ptLen, nonce, 12, aad, aadLen, pt, ct, 16, tag);
  mbedtls_gcm_free(&ctx); return rc==0;
}

static bool aes_gcm_decrypt(const uint8_t key[32], const uint8_t *ct, size_t ctLen,
                            const uint8_t *aad, size_t aadLen,
                            const uint8_t nonce[12], const uint8_t tag[16],
                            uint8_t *pt){
  mbedtls_gcm_context ctx; mbedtls_gcm_init(&ctx);
  if(mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256)!=0){ mbedtls_gcm_free(&ctx); return false; }
  int rc = mbedtls_gcm_auth_decrypt(&ctx, ctLen, nonce, 12, aad, aadLen, tag, 16, ct, pt);
  mbedtls_gcm_free(&ctx); return rc==0;
}

// ---------------------------- IDENTITY ---------------------------------
struct Identity {
  mbedtls_ecp_keypair kp;           // P-256 identity keypair
  bool ready=false;

  void init(){
    mbedtls_ecp_keypair_init(&kp);
    mbedtls_ecp_group_load(&kp.grp, MBEDTLS_ECP_DP_SECP256R1);
    loadOrCreate();
  }

  void deriveKek(uint8_t out[32]){
    // Derive a Key-Encryption-Key (KEK) from eFuse MAC via HKDF-SHA256
    uint64_t mac = ESP.getEfuseMac();
    uint8_t salt[8]; memcpy(salt, &mac, 8);
    const uint8_t info[] = "SPACE-DOA-KEK-v1";
    uint8_t ikm[8]; memcpy(ikm, &mac, 8);
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                 salt, sizeof(salt), ikm, sizeof(ikm),
                 info, sizeof(info)-1, out, 32);
  }

  bool encryptPrivForNVS(const uint8_t *priv32, std::vector<uint8_t> &blob){
    uint8_t kek[32]; deriveKek(kek);
    uint8_t nonce[12]; esp_fill_random(nonce, sizeof(nonce));
    uint8_t tag[16]; blob.resize(12+32+16);
    if(!aes_gcm_encrypt(kek, priv32, 32, nullptr, 0, nonce, blob.data()+12, tag)) return false;
    memcpy(blob.data(), nonce, 12);
    memcpy(blob.data()+12+32, tag, 16);
    return true;
  }

  bool decryptPrivFromNVS(const uint8_t *blob, size_t blobLen, uint8_t *out32){
    if(blobLen!=12+32+16) return false;
    uint8_t kek[32]; deriveKek(kek);
    const uint8_t *nonce = blob;
    const uint8_t *ct    = blob+12;
    const uint8_t *tag   = blob+12+32;
    return aes_gcm_decrypt(kek, ct, 32, nullptr, 0, nonce, tag, out32);
  }

  void loadOrCreate(){
    Preferences pref; if(!pref.begin("spacedoa", false)) return;
    size_t L = pref.getBytesLength("id_priv");
    if(L==12+32+16){
      std::vector<uint8_t> blob(L);
      pref.getBytes("id_priv", blob.data(), blob.size());
      uint8_t d32[32];
      if(!decryptPrivFromNVS(blob.data(), blob.size(), d32)){ pref.end(); return; }
      mbedtls_mpi_read_binary(&kp.d, d32, 32);
      mbedtls_ecp_mul(&kp.grp, &kp.Q, &kp.d, &kp.grp.G, NULL, NULL);
      ready=true; pref.end(); return;
    }
    // Create new identity
    mbedtls_entropy_context entropy; mbedtls_ctr_drbg_context ctr;
    mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&ctr);
    const char *pers="esp32-id-gen";
    mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp, mbedtls_ctr_drbg_random, &ctr);
    uint8_t priv[32]; mbedtls_mpi_write_binary(&kp.d, priv, 32);
    std::vector<uint8_t> blob; if(encryptPrivForNVS(priv, blob)) pref.putBytes("id_priv", blob.data(), blob.size());
    ready=true; pref.end();
    mbedtls_ctr_drbg_free(&ctr); mbedtls_entropy_free(&entropy);
  }

  bool pubCompressed(uint8_t out33[33]){
    size_t olen=0;
    return mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, out33, 33)==0 && olen==33;
  }

  bool sign(const uint8_t *msg, size_t len, std::vector<uint8_t> &sig){
    uint8_t h[32]; mbedtls_sha256(msg, len, h, 0);
    size_t olen=0; sig.assign(80,0);
    int rc = mbedtls_ecdsa_write_signature(&kp, MBEDTLS_MD_SHA256, h, sizeof(h), sig.data(), &olen, NULL, NULL);
    if(rc!=0) return false; sig.resize(olen); return true;
  }

  static bool verify(const uint8_t pub33[33], const uint8_t *msg, size_t len, const uint8_t *sig, size_t sigLen){
    mbedtls_ecdsa_context ctx; mbedtls_ecdsa_init(&ctx);
    if(mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1)!=0){ mbedtls_ecdsa_free(&ctx); return false; }
    if(mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, pub33, 33)!=0){ mbedtls_ecdsa_free(&ctx); return false; }
    uint8_t h[32]; mbedtls_sha256(msg, len, h, 0);
    int rc = mbedtls_ecdsa_read_signature(&ctx, h, sizeof(h), sig, sigLen);
    mbedtls_ecdsa_free(&ctx); return rc==0;
  }
};

static Identity g_id;

// ---------------------------- PEER CONTROL -----------------------------
struct Peer { IPAddress ip; uint8_t pub[33]; };
static Peer g_allow[4]; static uint8_t g_allowCount=0;

static bool peerAllowed(const IPAddress& ip, const uint8_t pub[33]){
  for(uint8_t i=0;i<g_allowCount;i++){
    if(g_allow[i].ip==ip && memcmp(g_allow[i].pub,pub,33)==0) return true;
  }
  return false;
}

// Example: configure one ground peer on startup
static void configurePeers(){
  g_allowCount = 0;
  uint8_t groundPub[33] = {0}; // TODO: set real 33B compressed pubkey here
  g_allow[g_allowCount++] = {GROUND_HINT, {0}};
  memcpy(g_allow[0].pub, groundPub, 33);
}

// ---------------------------- BLOCKCHAIN -------------------------------
struct TxIn  { char prevTx[65]; uint32_t vout; };
struct TxOut { uint32_t amount; uint8_t toPub[33]; };

struct Transaction {
  uint32_t version{1};
  uint32_t timestamp{0};
  uint8_t  fromPub[33]{};
  uint8_t  inCount{0}, outCount{0};
  TxIn     vin[2];
  TxOut    vout[2];
  uint16_t sigLen{0};
  uint8_t  sig[80];
  char     txid[65];
};

struct UTXOEntry { char txid[65]; uint32_t idx; uint32_t amount; uint8_t toPub[33]; bool spent; };

struct BlockHeader {
  uint32_t version{1}; uint32_t index{0}; uint32_t timestamp{0};
  char prevHash[65]; char merkle[65]; uint32_t nonce{0}; char hash[65];
};
struct Block { BlockHeader h; uint8_t txCount{0}; Transaction tx[MAX_TX_PER_BLOCK]; };

static Block g_chain[MAX_BLOCKS]; static uint16_t g_height=0;
static UTXOEntry g_utxo[2*MAX_MEMPOOL]; static uint16_t g_utxoCount=0;
static Transaction g_mempool[MAX_MEMPOOL]; static uint16_t g_mempoolSize=0;
static SemaphoreHandle_t g_chainMtx, g_mempoolMtx;

// Deterministic serialization (canonical JSON) with bounds checks
static bool serializeTxCanonical(const Transaction& tx, char* buf, size_t bufLen, size_t& outLen){
  if(tx.inCount>2 || tx.outCount>2) return false;
  StaticJsonDocument<512> d;
  d["v"]=tx.version; d["t"]=tx.timestamp;
  JsonArray vin=d.createNestedArray("in");
  for(uint8_t i=0;i<tx.inCount;i++){ JsonArray a=vin.createNestedArray(); a.add(tx.vin[i].prevTx); a.add(tx.vin[i].vout); }
  JsonArray vout=d.createNestedArray("out");
  for(uint8_t i=0;i<tx.outCount;i++){ JsonArray a=vout.createNestedArray(); a.add(tx.vout[i].amount); char pkhex[67]; toHex(tx.vout[i].toPub,33,pkhex); a.add(pkhex); }
  outLen = serializeJson(d, buf, bufLen);
  return outLen>0 && outLen<bufLen;
}

static void calcTxId(Transaction &tx){
  char pre[512]; size_t n=0;
  if(!serializeTxCanonical(tx, pre, sizeof(pre), n)){ strncpy(tx.txid,"",1); return; }
  uint8_t h[32]; mbedtls_sha256((const uint8_t*)pre, n, h, 0); toHex(h,32,tx.txid);
}

static bool txValidPolicy(const Transaction& tx){
  uint32_t t = nowSec();
  if(tx.timestamp > t + TX_FRESH_WINDOW) return false;
  if(tx.timestamp + TX_FRESH_WINDOW < t) return false;

  uint32_t totalIn=0, totalOut=0;
  for(uint8_t i=0;i<tx.inCount;i++){
    bool found=false;
    for(uint16_t j=0;j<g_utxoCount;j++){
      if(!g_utxo[j].spent && strcmp(g_utxo[j].txid, tx.vin[i].prevTx)==0 && g_utxo[j].idx==tx.vin[i].vout){
        totalIn += g_utxo[j].amount; found=true; break;
      }
    }
    if(!found) return false;
  }
  for(uint8_t i=0;i<tx.outCount;i++) totalOut += tx.vout[i].amount;
  if(totalIn < totalOut) return false;
  uint32_t fee = totalIn - totalOut;
  return fee >= MIN_FEE_PER_TX;
}

static bool verifyTxSig(const Transaction &tx){
  char pre[512]; size_t n=0;
  if(!serializeTxCanonical(tx, pre, sizeof(pre), n)) return false;
  return Identity::verify(tx.fromPub,(const uint8_t*)pre,n,tx.sig,tx.sigLen);
}

static bool applyTxToUTXO(const Transaction &tx){
  // spend inputs
  for(uint8_t i=0;i<tx.inCount;i++){
    bool found=false;
    for(uint16_t j=0;j<g_utxoCount;j++){
      if(!g_utxo[j].spent && strcmp(g_utxo[j].txid, tx.vin[i].prevTx)==0 && g_utxo[j].idx==tx.vin[i].vout){
        if(memcmp(g_utxo[j].toPub, tx.fromPub, 33)!=0) return false; // ownership
        g_utxo[j].spent=true; found=true; break;
      }
    }
    if(!found) return false;
  }
  // add outputs
  for(uint8_t k=0;k<tx.outCount;k++){
    if(g_utxoCount >= (int)(sizeof(g_utxo)/sizeof(g_utxo[0]))) return false;
    strncpy(g_utxo[g_utxoCount].txid, tx.txid, 65);
    g_utxo[g_utxoCount].idx=k; g_utxo[g_utxoCount].amount=tx.vout[k].amount;
    memcpy(g_utxo[g_utxoCount].toPub, tx.vout[k].toPub, 33); g_utxo[g_utxoCount].spent=false;
    g_utxoCount++;
  }
  return true;
}

static void merkleRoot(const Transaction *tx, uint8_t n, char out64[65]){
  if(n==0){ memset(out64,'0',64); out64[64]='\0'; return; }
  std::vector<std::array<uint8_t,32>> layer; layer.reserve(n);
  for(uint8_t i=0;i<n;i++){ uint8_t h[32]; mbedtls_sha256((const uint8_t*)tx[i].txid, 64, h, 0); layer.push_back({}); memcpy(layer.back().data(), h, 32); }
  while(layer.size()>1){
    std::vector<std::array<uint8_t,32>> nxt;
    for(size_t i=0;i<layer.size(); i+=2){
      auto &a=layer[i]; auto &b=(i+1<layer.size()?layer[i+1]:layer[i]);
      uint8_t cat[64]; memcpy(cat,a.data(),32); memcpy(cat+32,b.data(),32);
      uint8_t h[32]; mbedtls_sha256(cat,64,h,0); nxt.push_back({}); memcpy(nxt.back().data(),h,32);
    }
    layer.swap(nxt);
  }
  toHex(layer[0].data(),32,out64);
}

static void hashBlockHeader(BlockHeader &bh){
  char buf[256];
  snprintf(buf,sizeof(buf), "%u%u%u%s%s%u", bh.version,bh.index,bh.timestamp,bh.prevHash,bh.merkle,bh.nonce);
  uint8_t h[32]; mbedtls_sha256((const uint8_t*)buf, strlen(buf), h, 0); toHex(h,32,bh.hash);
}

static bool pow_ok(const char* hex){
  for(uint32_t i=0;i<POW_ZEROS;i++){ if(hex[i]!='0') return false; }
  return true;
}

// --------------------------- PERSISTENCE -------------------------------
static bool fsWriteAtomic(const char* path, const uint8_t* data, size_t len){
  String tmp=String(path)+".tmp";
  File f=SD.open(tmp.c_str(), FILE_WRITE); if(!f) return false;
  size_t w=f.write(data,len); f.flush(); f.close();
  if(w!=len){ SD.remove(tmp.c_str()); return false; }
  if(SD.exists(path)) SD.remove(path);
  return SD.rename(tmp.c_str(), path);
}
static bool appendJournal(const char* line){
  File f=SD.open(JOURNAL, FILE_APPEND); if(!f) return false;
  size_t w=f.println(line); f.flush(); f.close(); return w>0;
}

static bool ensureChainDir(){
  if(!SD.exists(CHAIN_DIR)) return SD.mkdir(CHAIN_DIR);
  return true;
}

static bool saveBlockToSD(const Block& b){
  char path[64]; snprintf(path,sizeof(path), "%s/block_%u.json", CHAIN_DIR, b.h.index);
  StaticJsonDocument<1024> d; // small blocks
  JsonObject h=d.createNestedObject("h");
  h["v"]=b.h.version; h["i"]=b.h.index; h["t"]=b.h.timestamp; h["prev"]=b.h.prevHash; h["mrk"]=b.h.merkle; h["n"]=b.h.nonce; h["h"]=b.h.hash;
  d["txc"]=b.txCount;
  JsonArray arr = d.createNestedArray("tx");
  for(uint8_t i=0;i<b.txCount;i++){
    JsonObject x = arr.createNestedObject();
    x["v"]=b.tx[i].version; x["t"]=b.tx[i].timestamp; x["fc"]=b.tx[i].inCount; x["tc"]=b.tx[i].outCount; x["id"]=b.tx[i].txid;
  }
  char buf[2048]; size_t L = serializeJson(d, buf, sizeof(buf));
  if(L==0) return false; return fsWriteAtomic(path,(const uint8_t*)buf,L);
}

// ------------------------------ NETWORK --------------------------------
WiFiUDP g_udp;

enum MsgType: uint8_t { MSG_TX=1, MSG_BLOCK=2, MSG_PING=3, MSG_PONG=4, MSG_HELLO=100, MSG_HELLO_ACK=101 };

#pragma pack(push,1)
struct WireHeader {
  uint32_t ver;
  uint32_t ts;
  uint32_t seq;
  uint8_t  type;
};
#pragma pack(pop)

static void packHeader(WireHeader &h, uint8_t *out){ memcpy(out,&h,sizeof(WireHeader)); }
static bool withinWindow(uint32_t ts){ uint32_t n=nowSec(); if(ts > n + RX_WINDOW_SEC) return false; if(ts + RX_WINDOW_SEC < n) return false; return true; }

struct Session {
  bool established=false;
  IPAddress peer{};
  uint8_t k_enc[32];     // encryption key
  uint8_t k_mac[32];     // handshake MAC key
  uint8_t noncePrefix[4];// per-session random prefix
  uint32_t rxSeq=0;
  uint32_t txSeq=0;
  uint8_t peerIdPub[33]{};
  uint32_t lastRxTs=0;
};
static Session g_sess;

// Handshake state (ephemeral keypair + nonces)
struct Ephemeral {
  mbedtls_ecp_keypair kp; uint8_t pub[33]; uint8_t nonce[12]; bool have=false;
  Ephemeral(){ mbedtls_ecp_keypair_init(&kp); }
  ~Ephemeral(){ mbedtls_ecp_keypair_free(&kp); }
};
static Ephemeral g_eph;

static void eph_make(){
  if(g_eph.have) return;
  mbedtls_ecp_group_load(&g_eph.kp.grp, MBEDTLS_ECP_DP_SECP256R1);
  mbedtls_entropy_context entropy; mbedtls_ctr_drbg_context ctr;
  mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&ctr);
  const char* pers="eph-gen";
  mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,(const unsigned char*)pers, strlen(pers));
  mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &g_eph.kp, mbedtls_ctr_drbg_random,&ctr);
  size_t olen=0; mbedtls_ecp_point_write_binary(&g_eph.kp.grp,&g_eph.kp.Q,MBEDTLS_ECP_PF_COMPRESSED,&olen,g_eph.pub,33);
  esp_fill_random(g_eph.nonce,12);
  g_eph.have=true;
  mbedtls_ctr_drbg_free(&ctr); mbedtls_entropy_free(&entropy);
}

static void make_msg_nonce(uint8_t outNonce[12], uint32_t ts, uint32_t seq, const uint8_t prefix[4]){
  memcpy(outNonce, prefix, 4);
  memcpy(outNonce+4, &seq, 4);
  memcpy(outNonce+8, &ts, 4);
}

static void hmac_sha256(const uint8_t key[32], const uint8_t* m, size_t mlen, uint8_t out[32]){
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_context_t ctx; mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, md, 1);
  mbedtls_md_hmac_starts(&ctx, key, 32);
  mbedtls_md_hmac_update(&ctx, m, mlen);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

static size_t build_transcript(uint8_t *buf, size_t max,
                               uint32_t ver,
                               const uint8_t idA[33], const uint8_t ephA[33], const uint8_t nonceA[12], uint32_t tsA,
                               const uint8_t idB[33], const uint8_t ephB[33], const uint8_t nonceB[12], uint32_t tsB){
  if(max < (4+4+33+33+12+4+33+33+12)) return 0;
  size_t off=0;
  memcpy(buf+off, &ver, 4); off+=4;
  memcpy(buf+off, &tsA, 4); off+=4;
  memcpy(buf+off, idA, 33); off+=33;
  memcpy(buf+off, ephA, 33); off+=33;
  memcpy(buf+off, nonceA, 12); off+=12;
  memcpy(buf+off, &tsB, 4); off+=4;
  memcpy(buf+off, idB, 33); off+=33;
  memcpy(buf+off, ephB, 33); off+=33;
  memcpy(buf+off, nonceB, 12); off+=12;
  return off;
}

static bool derive_session_keys(const uint8_t peerEphPub33[33], const uint8_t nonceA[12], const uint8_t nonceB[12],
                                const uint8_t myIdPub[33], const uint8_t peerIdPub[33],
                                uint8_t out_k_enc[32], uint8_t out_k_mac[32], uint8_t out_noncePrefix[4]){
  // ECDH shared secret
  mbedtls_ecp_point Qp; mbedtls_ecp_point_init(&Qp);
  if(mbedtls_ecp_point_read_binary(&g_eph.kp.grp, &Qp, peerEphPub33, 33)!=0){ mbedtls_ecp_point_free(&Qp); return false; }
  mbedtls_mpi Z; mbedtls_mpi_init(&Z);
  int rc = mbedtls_ecdh_compute_shared(&g_eph.kp.grp, &Z, &Qp, &g_eph.kp.d, NULL, NULL);
  if(rc!=0){ mbedtls_mpi_free(&Z); mbedtls_ecp_point_free(&Qp); return false; }
  uint8_t zbin[32]; mbedtls_mpi_write_binary(&Z, zbin, 32);
  mbedtls_mpi_free(&Z); mbedtls_ecp_point_free(&Qp);

  uint8_t salt[24]; memcpy(salt, nonceA, 12); memcpy(salt+12, nonceB, 12);

  uint8_t info[13 + 33 + 33 + 33 + 33];
  size_t off=0; const char* tag="SPACE-DOA v2"; memcpy(info+off, tag, 12); off+=12; info[off++]=0;
  memcpy(info+off, myIdPub, 33); off+=33;
  memcpy(info+off, peerIdPub, 33); off+=33;
  memcpy(info+off, g_eph.pub, 33); off+=33;
  memcpy(info+off, peerEphPub33, 33); off+=33;

  uint8_t okm[64];
  mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, sizeof(salt),
               zbin, sizeof(zbin), info, off, okm, sizeof(okm));
  memcpy(out_k_enc, okm, 32);
  memcpy(out_k_mac, okm+32, 32);
  esp_fill_random(out_noncePrefix, 4);
  return true;
}

// ---- HELLO / ACK ----
static bool send_hello(const IPAddress& dst, uint32_t *helloTsOut){
  if(!g_id.ready) return false; eph_make();
  WireHeader h{PROTOCOL_VERSION, nowSec(), 0, MSG_HELLO};
  if(helloTsOut) *helloTsOut = h.ts;

  StaticJsonDocument<256> d;
  uint8_t myId[33]; g_id.pubCompressed(myId);
  char idhex[67]; toHex(myId,33,idhex);
  char ephhex[67]; toHex(g_eph.pub,33,ephhex);
  char nhex[25];  toHex(g_eph.nonce,12,nhex);

  d["id"]=idhex; d["eph"]=ephhex; d["na"]=nhex; d["ts"]=h.ts;

  uint8_t hdr[sizeof(WireHeader)]; packHeader(h,hdr);
  char body[256]; size_t len = serializeJson(d, body, sizeof(body)); if(len==0) return false;

  g_udp.beginPacket(dst, UDP_PORT); g_udp.write(hdr, sizeof(hdr)); g_udp.write((uint8_t*)body, len);
  bool ok = g_udp.endPacket(); if(ok){ Serial.println("[HELLO] sent"); ledBlink(LED_TX); }
  return ok;
}

static bool send_hello_ack(const IPAddress& dst, const uint8_t peerId[33], const uint8_t peerEph[33], const uint8_t peerNonceA[12], uint32_t tsA){
  if(!g_id.ready) return false; eph_make();
  uint8_t myId[33]; g_id.pubCompressed(myId);

  uint8_t k_enc[32], k_mac[32], noncePrefix[4];
  if(!derive_session_keys(peerEph, peerNonceA, g_eph.nonce, myId, peerId, k_enc, k_mac, noncePrefix)) return false;

  uint8_t transcript[256]; uint32_t tsB = nowSec();
  size_t tlen = build_transcript(transcript, sizeof(transcript), PROTOCOL_VERSION,
                                 peerId, peerEph, peerNonceA, tsA,
                                 myId, g_eph.pub, g_eph.nonce, tsB);
  uint8_t mac[32]; hmac_sha256(k_mac, transcript, tlen, mac);
  char machex[65]; toHex(mac,32,machex);

  WireHeader h{PROTOCOL_VERSION, tsB, 0, MSG_HELLO_ACK};
  StaticJsonDocument<320> d;
  char idhex[67]; toHex(myId,33,idhex);
  char ephhex[67]; toHex(g_eph.pub,33,ephhex);
  char nhex[25];  toHex(g_eph.nonce,12,nhex);
  uint8_t pref4[4]; memcpy(pref4, noncePrefix, 4); char nPrefHex[9]; toHex(pref4,4,nPrefHex);

  d["id"]=idhex; d["eph"]=ephhex; d["nb"]=nhex; d["np"]=nPrefHex; d["mac"]=machex; d["ts"]=h.ts;

  uint8_t hdr[sizeof(WireHeader)]; packHeader(h,hdr);
  char body[320]; size_t len = serializeJson(d, body, sizeof(body)); if(len==0) return false;

  g_udp.beginPacket(dst, UDP_PORT); g_udp.write(hdr, sizeof(hdr)); g_udp.write((uint8_t*)body, len);
  bool ok = g_udp.endPacket(); if(ok){ Serial.println("[HELLO_ACK] sent"); ledBlink(LED_TX); }

  // stage session (confirmed on first encrypted ping/pkt)
  g_sess.established = true; g_sess.peer = dst;
  memcpy(g_sess.k_enc, k_enc, 32); memcpy(g_sess.k_mac, k_mac, 32); memcpy(g_sess.noncePrefix, noncePrefix, 4);
  memcpy(g_sess.peerIdPub, peerId, 33); g_sess.rxSeq=0; g_sess.txSeq=0; g_sess.lastRxTs=0;
  return ok;
}

static bool process_hello(const IPAddress& from, const uint8_t *body, size_t len){
  if(len==0) return false; StaticJsonDocument<256> d;
  if(deserializeJson(d, body, len)!=DeserializationError::Ok) return false;
  const char* idhex=d["id"]; const char* ephhex=d["eph"]; const char* nhex=d["na"]; uint32_t tsA=d["ts"]|0;
  if(!idhex||!ephhex||!nhex) return false; if(!withinWindow(tsA)) return false;

  uint8_t peerId[33], peerEph[33], nonceA[12];
  if(!fromHex(idhex, peerId, 33)) return false;
  if(!fromHex(ephhex, peerEph, 33)) return false;
  if(!fromHex(nhex, nonceA, 12)) return false;

  if(!peerAllowed(from, peerId)){ Serial.println("[HELLO] rejected: allowlist"); return false; }
  return send_hello_ack(from, peerId, peerEph, nonceA, tsA);
}

static uint32_t g_lastHelloTs=0;
static bool process_hello_ack(const IPAddress& from, const uint8_t *body, size_t len){
  if(!g_eph.have) return false; if(len==0) return false; StaticJsonDocument<320> d;
  if(deserializeJson(d, body, len)!=DeserializationError::Ok) return false;
  const char* idhex=d["id"]; const char* ephhex=d["eph"]; const char* nb=d["nb"]; const char* macHex=d["mac"]; const char* nPrefHex=d["np"]; uint32_t tsB=d["ts"]|0;
  if(!idhex||!ephhex||!nb||!macHex||!nPrefHex) return false; if(!withinWindow(tsB)) return false;

  uint8_t peerId[33], peerEph[33], nonceB[12], mac[32], noncePrefix[4];
  if(!fromHex(idhex, peerId, 33)) return false;
  if(!fromHex(ephhex, peerEph, 33)) return false;
  if(!fromHex(nb, nonceB, 12)) return false;
  if(!fromHex(macHex, mac, 32)) return false;
  if(!fromHex(nPrefHex, noncePrefix, 4)) return false;

  if(!peerAllowed(from, peerId)){ Serial.println("[HELLO_ACK] rejected: allowlist"); return false; }

  uint8_t myId[33]; g_id.pubCompressed(myId);
  uint8_t k_enc[32], k_mac[32], junk[4];
  if(!derive_session_keys(peerEph, g_eph.nonce, nonceB, myId, peerId, k_enc, k_mac, junk)) return false;

  uint8_t transcript[256];
  size_t tlen = build_transcript(transcript, sizeof(transcript), PROTOCOL_VERSION,
                                 myId, g_eph.pub, g_eph.nonce, g_lastHelloTs,
                                 peerId, peerEph, nonceB, tsB);
  uint8_t macCalc[32]; hmac_sha256(k_mac, transcript, tlen, macCalc);
  if(memcmp(macCalc, mac, 32)!=0){ Serial.println("[HELLO_ACK] MAC verify failed"); return false; }

  g_sess.established = true; g_sess.peer = from; memcpy(g_sess.k_enc, k_enc, 32); memcpy(g_sess.k_mac, k_mac, 32); memcpy(g_sess.noncePrefix, noncePrefix, 4);
  memcpy(g_sess.peerIdPub, peerId, 33); g_sess.rxSeq=0; g_sess.txSeq=0; g_sess.lastRxTs=0;
  Serial.println("[SESSION] established"); ledBlink(LED_STATUS,150);
  return true;
}

// --------------------- ENCRYPTED SEND/RECV HELPERS ---------------------
static bool send_encrypted(const IPAddress& dst, MsgType type, const uint8_t* payload, size_t payLen){
  if(!g_sess.established) return false;
  if(!bucket_allow()) { Serial.println("[RATE] drop (bucket)"); return false; }

  WireHeader h{PROTOCOL_VERSION, nowSec(), ++g_sess.txSeq, (uint8_t)type};
  if(!withinWindow(h.ts)) return false; // local clock sanity
  uint8_t aad[sizeof(WireHeader)]; packHeader(h,aad);

  uint8_t nonce[12]; make_msg_nonce(nonce, h.ts, h.seq, g_sess.noncePrefix);
  uint8_t ct[MAX_MSG_SIZE]; uint8_t tag[16];
  if(payLen>MAX_MSG_SIZE){ Serial.println("[SEND] payload too big"); return false; }
  if(!aes_gcm_encrypt(g_sess.k_enc, payload, payLen, aad, sizeof(aad), nonce, ct, tag)) return false;

  g_udp.beginPacket(dst, UDP_PORT);
  g_udp.write(aad, sizeof(aad));
  g_udp.write(ct, payLen);
  g_udp.write(tag, 16);
  bool ok = g_udp.endPacket(); if(ok){ ledBlink(LED_TX); }
  return ok;
}

static bool recv_encrypted(const IPAddress& from, const uint8_t* pkt, size_t len, MsgType& typeOut, std::vector<uint8_t>& out){
  if(len < sizeof(WireHeader)+16) return false;
  WireHeader h; memcpy(&h, pkt, sizeof(WireHeader));
  if(h.ver!=PROTOCOL_VERSION) return false; if(!withinWindow(h.ts)) return false;
  if(h.seq <= g_sess.rxSeq && (h.ts <= g_sess.lastRxTs)) return false; // basic replay/order defense

  uint8_t nonce[12]; make_msg_nonce(nonce, h.ts, h.seq, g_sess.noncePrefix);
  const uint8_t* ct = pkt + sizeof(WireHeader);
  size_t ctLen = len - sizeof(WireHeader) - 16;
  const uint8_t* tag = pkt + sizeof(WireHeader) + ctLen;

  out.assign(ctLen, 0);
  uint8_t aad[sizeof(WireHeader)]; memcpy(aad, pkt, sizeof(WireHeader));
  if(!aes_gcm_decrypt(g_sess.k_enc, ct, ctLen, aad, sizeof(aad), nonce, tag, out.data())) return false;

  g_sess.rxSeq = h.seq; g_sess.lastRxTs = h.ts; typeOut = (MsgType)h.type; ledBlink(LED_RX);
  return true;
}

// ----------------------- APPLICATION MESSAGES -------------------------
static bool encode_tx_payload(const Transaction& tx, std::vector<uint8_t>& out){
  StaticJsonDocument<768> d;
  d["v"]=tx.version; d["t"]=tx.timestamp; d["fc"]=tx.inCount; d["tc"]=tx.outCount; d["id"]=tx.txid;
  JsonArray vin=d.createNestedArray("in"); for(uint8_t i=0;i<tx.inCount;i++){ JsonArray a=vin.createNestedArray(); a.add(tx.vin[i].prevTx); a.add(tx.vin[i].vout);}  
  JsonArray vout=d.createNestedArray("out"); for(uint8_t i=0;i<tx.outCount;i++){ JsonArray a=vout.createNestedArray(); a.add(tx.vout[i].amount); char pk[67]; toHex(tx.vout[i].toPub,33,pk); a.add(pk);}  
  char buf[768]; size_t L = serializeJson(d, buf, sizeof(buf)); if(L==0) return false; out.assign(buf, buf+L); return true;
}

static bool decode_tx_payload(const uint8_t* data, size_t len, Transaction& tx){
  StaticJsonDocument<768> d; if(deserializeJson(d, data, len)!=DeserializationError::Ok) return false;
  tx.version=d["v"]|1; tx.timestamp=d["t"]|0; tx.inCount=d["fc"]|0; tx.outCount=d["tc"]|0;
  strlcpy(tx.txid, d["id"]|"", sizeof(tx.txid));
  JsonArray vin=d["in"]; for(uint8_t i=0;i<tx.inCount && i<2;i++){ strlcpy(tx.vin[i].prevTx, vin[i][0] | "", sizeof(tx.vin[i].prevTx)); tx.vin[i].vout = vin[i][1] | 0; }
  JsonArray vout=d["out"]; for(uint8_t i=0;i<tx.outCount && i<2;i++){ tx.vout[i].amount = vout[i][0] | 0; const char* pkhex=vout[i][1] | ""; if(!fromHex(pkhex, tx.vout[i].toPub, 33)) return false; }
  return true;
}

static bool encode_block_payload(const Block& b, std::vector<uint8_t>& out){
  StaticJsonDocument<1536> d; JsonObject h=d.createNestedObject("h");
  h["v"]=b.h.version; h["i"]=b.h.index; h["t"]=b.h.timestamp; h["prev"]=b.h.prevHash; h["mrk"]=b.h.merkle; h["n"]=b.h.nonce; h["h"]=b.h.hash;
  d["txc"]=b.txCount; JsonArray arr = d.createNestedArray("tx");
  for(uint8_t i=0;i<b.txCount;i++){ JsonObject x = arr.createNestedObject(); x["id"]=b.tx[i].txid; }
  char buf[2048]; size_t L = serializeJson(d, buf, sizeof(buf)); if(L==0) return false; out.assign(buf, buf+L); return true;
}

static bool decode_block_payload(const uint8_t* data, size_t len, Block& b){
  StaticJsonDocument<1536> d; if(deserializeJson(d, data, len)!=DeserializationError::Ok) return false;
  JsonObject h = d["h"]; b.h.version=h["v"]|1; b.h.index=h["i"]|0; b.h.timestamp=h["t"]|0; strlcpy(b.h.prevHash, h["prev"]|"", sizeof(b.h.prevHash)); strlcpy(b.h.merkle, h["mrk"]|"", sizeof(b.h.merkle)); b.h.nonce=h["n"]|0; strlcpy(b.h.hash, h["h"]|"", sizeof(b.h.hash));
  b.txCount=d["txc"]|0; if(b.txCount>MAX_TX_PER_BLOCK) b.txCount=MAX_TX_PER_BLOCK;
  return true;
}

// ----------------------- MINER / CHAIN MGMT ---------------------------
static int findMempoolTxById(const char* txid){
  for(uint16_t i=0;i<g_mempoolSize;i++){
    if(strncmp(g_mempool[i].txid, txid, 64)==0) return (int)i;
  }
  return -1;
}

static void removeMempoolAt(uint16_t idx){
  if(idx>=g_mempoolSize) return;
  for(uint16_t i=idx+1;i<g_mempoolSize;i++) g_mempool[i-1] = g_mempool[i];
  if(g_mempoolSize>0) g_mempoolSize--;
}

static void removeMempoolManyByMask(const bool *mask, uint16_t n){
  // compact mempool, skipping those with mask[i]==true
  uint16_t w=0;
  for(uint16_t i=0;i<g_mempoolSize;i++){
    if(i<n && mask[i]) continue;
    if(w!=i) g_mempool[w]=g_mempool[i];
    w++;
  }
  g_mempoolSize = w;
}

static bool addTxToMempool(const Transaction& tx){
  // Check duplicates
  if(findMempoolTxById(tx.txid)>=0) return false;

  // Policy checks (freshness, fee vs inputs/outputs) and signature
  if(!txValidPolicy(tx)) return false;
  if(!verifyTxSig(tx)) return false;

  // Do not actually mutate UTXO here; only on block apply.
  if(g_mempoolSize >= MAX_MEMPOOL) return false;
  g_mempool[g_mempoolSize++] = tx;
  return true;
}

// Validate a block header/body against current tip (without mutating)
static bool validateBlock(const Block& b){
  // Index should be our next height
  if(b.h.index != g_height) return false;

  // Previous hash must match our tip (or be zero for genesis)
  if(g_height==0){
    // Accept either zeros in prevHash or empty string
    char zeros[65]; memset(zeros,'0',64); zeros[64]='\0';
    if(strncmp(b.h.prevHash, zeros, 64)!=0) return false;
  } else {
    if(strncmp(b.h.prevHash, g_chain[g_height-1].h.hash, 64)!=0) return false;
  }

  // Deterministic merkle
  char mrk[65]; merkleRoot(b.tx, b.txCount, mrk);
  if(strncmp(mrk, b.h.merkle, 64)!=0) return false;

  // Hash header with given nonce and check PoW target
  BlockHeader tmp = b.h;
  hashBlockHeader(tmp);
  if(strncmp(tmp.hash, b.h.hash, 64)!=0) return false;
  if(!pow_ok(b.h.hash)) return false;

  // Validate each TX w.r.t. current UTXO (policy + sig + ownership)
  for(uint8_t i=0;i<b.txCount;i++){
    if(!verifyTxSig(b.tx[i])) return false;
    if(!txValidPolicy(b.tx[i])) return false;

    // Dry-run UTXO application in a small scratch set to detect double-spends inside the same block
    // (Shallow copy current UTXO footing)
    UTXOEntry scratch[2*MAX_MEMPOOL];
    uint16_t scratchCount = g_utxoCount;
    for(uint16_t u=0; u<g_utxoCount; u++) scratch[u]=g_utxo[u];

    // Spend inputs
    for(uint8_t ii=0; ii<b.tx[i].inCount; ii++){
      bool found=false;
      for(uint16_t u=0; u<scratchCount; u++){
        if(!scratch[u].spent &&
           strcmp(scratch[u].txid, b.tx[i].vin[ii].prevTx)==0 &&
           scratch[u].idx == b.tx[i].vin[ii].vout){
          if(memcmp(scratch[u].toPub, b.tx[i].fromPub, 33)!=0) return false;
          scratch[u].spent = true;
          found=true; break;
        }
      }
      if(!found) return false; // missing UTXO referenced
    }
    // Add outputs into scratch
    for(uint8_t oo=0; oo<b.tx[i].outCount; oo++){
      if(scratchCount >= (int)(sizeof(scratch)/sizeof(scratch[0]))) return false;
      strncpy(scratch[scratchCount].txid, b.tx[i].txid, 65);
      scratch[scratchCount].idx = oo;
      scratch[scratchCount].amount = b.tx[i].vout[oo].amount;
      memcpy(scratch[scratchCount].toPub, b.tx[i].vout[oo].toPub, 33);
      scratch[scratchCount].spent = false;
      scratchCount++;
    }
  }
  return true;
}

// Mutate: apply block to chain + UTXO, persist, prune mempool
static bool applyBlock(const Block& b){
  if(!validateBlock(b)) return false;

  // Apply TX to UTXO
  for(uint8_t i=0;i<b.txCount;i++){
    if(!applyTxToUTXO(b.tx[i])) return false;
  }

  // Append to in-memory chain
  if(g_height >= MAX_BLOCKS) return false;
  g_chain[g_height] = b;
  g_height++;

  // Persist to SD (best-effort, but we fail hard if write fails)
  if(!ensureChainDir()) return false;
  if(!saveBlockToSD(b)) return false;

  // Journal line
  char jline[160];
  snprintf(jline, sizeof(jline), "APPEND %u %s %s", b.h.index, b.h.hash, b.h.merkle);
  appendJournal(jline);

  // Remove included TX from mempool
  if(b.txCount>0){
    // Build quick lookup set of txids in this block
    bool mask[MAX_MEMPOOL]; memset(mask, 0, sizeof(mask));
    for(uint8_t i=0;i<b.txCount;i++){
      int mp = findMempoolTxById(b.tx[i].txid);
      if(mp>=0 && (uint16_t)mp < g_mempoolSize) mask[mp]=true;
    }
    removeMempoolManyByMask(mask, g_mempoolSize);
  }
  return true;
}

static void broadcastBlock(const Block& b){
  if(!g_sess.established) return;
  std::vector<uint8_t> payload;
  if(!encode_block_payload(b, payload)) return;
  send_encrypted(g_sess.peer, MSG_BLOCK, payload.data(), payload.size());
}

static void fillPrevHash(char out64[65]){
  if(g_height==0){
    memset(out64, '0', 64); out64[64]='\0';
  } else {
    strlcpy(out64, g_chain[g_height-1].h.hash, 65);
  }
}

static void buildBlockHeader(Block &b){
  b.h.version = 1;
  b.h.index   = g_height;
  b.h.timestamp = nowSec();
  fillPrevHash(b.h.prevHash);
  merkleRoot(b.tx, b.txCount, b.h.merkle);
  b.h.nonce = 0;
  hashBlockHeader(b.h); // initial (likely not meeting PoW yet)
}

static void mine_block(){
  // Snapshot mempool under lock
  Transaction local[MAX_TX_PER_BLOCK];
  uint8_t count=0;

  xSemaphoreTake(g_mempoolMtx, portMAX_DELAY);
  uint8_t n = std::min<uint16_t>(g_mempoolSize, MAX_TX_PER_BLOCK);
  for(uint8_t i=0;i<n;i++) local[i] = g_mempool[i];
  count = n;
  xSemaphoreGive(g_mempoolMtx);

  if(count==0) return;

  // Construct candidate block (do NOT mutate global state yet)
  Block b; memset(&b, 0, sizeof(b));
  b.txCount = count;
  for(uint8_t i=0;i<count;i++){
    // Ensure txid is populated (if source forgot)
    Transaction &tx = local[i];
    if(tx.txid[0]==0) { calcTxId(tx); }
    b.tx[i] = tx;
  }

  // Block header fields + initial hash
  buildBlockHeader(b);

  // Quick full-validate against current tip (dry-run) before PoW
  xSemaphoreTake(g_chainMtx, portMAX_DELAY);
  bool okPre = validateBlock(b);
  xSemaphoreGive(g_chainMtx);
  if(!okPre) return;

  // Mine: increment nonce until pow_ok
  uint32_t nonce=0;
  while(true){
    b.h.nonce = nonce++;
    hashBlockHeader(b.h);
    if(pow_ok(b.h.hash)) break;

    // optional low-duty blink
    if((nonce & 0x3FFF)==0){ ledBlink(LED_STATUS, 10); }
    // watchdogs can be petted here if you have them
  }

  // Apply to chain under lock
  xSemaphoreTake(g_chainMtx, portMAX_DELAY);
  bool applied = applyBlock(b);
  xSemaphoreGive(g_chainMtx);

  if(applied){
    broadcastBlock(b);
    ledBlink(LED_STATUS, 120);
  }
}

// ----------------------- APP MSG DISPATCH (TX/BLOCK) -------------------
static bool process_tx_msg(const IPAddress& from, const uint8_t *body, size_t len){
  Transaction tx;
  if(!decode_tx_payload(body, len, tx)) return false;

  // If txid missing, compute it
  if(tx.txid[0]==0) calcTxId(tx);

  // Mempool add under lock
  xSemaphoreTake(g_mempoolMtx, portMAX_DELAY);
  bool ok = addTxToMempool(tx);
  xSemaphoreGive(g_mempoolMtx);

  if(ok){
    // Optionally gossip to peer (light rebroadcast)
    if(g_sess.established && from != g_sess.peer){
      std::vector<uint8_t> p; if(encode_tx_payload(tx, p)){
        send_encrypted(g_sess.peer, MSG_TX, p.data(), p.size());
      }
    }
    ledBlink(LED_RX, 30);
  }
  return ok;
}

static bool process_block_msg(const IPAddress& /*from*/, const uint8_t *body, size_t len){
  Block b;
  if(!decode_block_payload(body, len, b)) return false;

  // Recompute merkle/hash to normalize
  merkleRoot(b.tx, b.txCount, b.h.merkle);
  hashBlockHeader(b.h);

  xSemaphoreTake(g_chainMtx, portMAX_DELAY);
  bool ok = applyBlock(b);
  xSemaphoreGive(g_chainMtx);

  if(ok) ledBlink(LED_RX, 60);
  return ok;
}

// Optional helper to route decrypted app messages
static void process_app_msg(const IPAddress& from, MsgType type, const uint8_t* payload, size_t len){
  switch(type){
    case MSG_TX:    process_tx_msg(from, payload, len);    break;
    case MSG_BLOCK: process_block_msg(from, payload, len); break;
    default: /* ignore others here */ break;
  }
}
