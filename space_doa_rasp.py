#!/usr/bin/env python3
"""
SPACE DOA - Raspberry Pi CubeSat Blockchain Node
Production-Ready Implementation v3.0.1

"""

import os
import time
import hashlib
import json
import socket
import struct
import threading
import queue
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# --- Third-party libraries ---
# Install using: pip install cryptography RPi.GPIO spidev smbus
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import RPi.GPIO as GPIO
import spidev
import smbus
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import constant_time
import os, secrets


# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    # GPIO Pin Configuration
    LED_STATUS = 17
    LED_TX = 27
    LED_RX = 18
    LED_ERROR = 25

    # I2C Configuration
    I2C_BUS = 1
    IMU_ADDRESS = 0x68  # MPU9250/MPU6050

    # Network Configuration
    UDP_IP = "0.0.0.0"  # Listen on all interfaces
    UDP_PORT = 8888
    ESP32_IP = "192.168.1.100" # Manually set the ESP32's IP for now
    PROTOCOL_VERSION = 1
    RX_WINDOW_SEC = 60  # Accept messages within ±60s of current time

    # Rate Limiting (Token Bucket Algorithm)
    TOKEN_BUCKET_RATE = 6  # msgs per second allowed
    TOKEN_BUCKET_SIZE = 30  # burst size

    # Blockchain Parameters
    MAX_TX_PER_BLOCK = 10
    DIFFICULTY_LEADING_ZEROES = 4
    BLOCK_REWARD = 50000000  # 0.5 "coins" in satoshis
    COINBASE_MATURITY = 10 # Blocks before coinbase can be spent

    # Storage
    CHAIN_FILE = "blockchain.json"
    KEY_FILE = "node_key.pem"
    KEY_PASSWORD = b"space-doa-is-secure" # Password to encrypt the private key on disk

# ---------------------------- PROTOCOL / MESSAGES ----------------------------
class MsgType:
    TX = 1
    BLOCK = 2
    PING = 3
    PONG = 4
    INV = 5
    GETBLOCK = 6
    HELLO = 100
    HELLO_ACK = 101

WIRE_STRUCT = "!IIIB"   # ver(uint32), ts(uint32), seq(uint32), type(uint8)
WIRE_HDR_LEN = 13
MAX_MSG_SIZE = 2048     # safety cap for JSON payloads
RX_WINDOW_SEC = Config.RX_WINDOW_SEC

# Miner / schedulers (match ESP cadence)
HELLO_RETRY_MS    = 3000
PING_INTERVAL_MS  = 10000
MINE_INTERVAL_SEC = 20
MEMPOOL_MINE_MIN  = 3

INV_ANNOUNCE_MS   = 30000
REBROADCAST_MS    = 15000
REB_TX_BURST      = 2
POW_ZEROS         = Config.DIFFICULTY_LEADING_ZEROES  # leading zeros in hex
PROTOCOL_VERSION  = Config.PROTOCOL_VERSION

# =============================================================================
# UTILITY & DATA STRUCTURES
# =============================================================================

def now_sec() -> int:
    # use wall-clock for cross-device RX window checks
    return int(time.time())


def to_hex(data: bytes) -> str:
    return data.hex()

def from_hex(data_str: str) -> bytes:
    return bytes.fromhex(data_str)

def to_hex_bytes(b: bytes) -> str: return b.hex()
    
class UTXO:
    def __init__(self, txid: str, index: int, amount: int, address: str):
        self.txid = txid
        self.index = index
        self.amount = amount
        self.address = address

    def __repr__(self):
        return f"UTXO(txid={self.txid[:10]}..., index={self.index}, amount={self.amount}, address={self.address})"

# =============================================================================
# CRYPTOGRAPHY LAYER
# =============================================================================

class CryptoLayer:
    def __init__(self):
        self._private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self._public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.address: Optional[str] = None
        self._net_key: Optional[bytes] = None

    def initialize(self):
        """Load keys or generate new ones if they don't exist."""
        if os.path.exists(Config.KEY_FILE):
            print("[CRYPTO] Loading existing private key...")
            self.load_private_key(Config.KEY_FILE, Config.KEY_PASSWORD)
        else:
            print("[CRYPTO] No key file found. Generating new identity...")
            self.generate_keys()
            self.save_private_key(Config.KEY_FILE, Config.KEY_PASSWORD)
        
        self.address = self.generate_address(self.get_public_key_compressed())
        print(f"[CRYPTO] Node Address: {self.address}")
        
        # Generate a stable network key from the private key for AES-GCM
        self._net_key = hashlib.sha256(self._private_key.private_numbers().private_value.to_bytes(32, 'big')).digest()
        print("[CRYPTO] Network encryption key derived.")

    def generate_keys(self):
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()

    def save_private_key(self, filename: str, password: bytes):
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        with open(filename, 'wb') as f:
            f.write(pem)

    def load_private_key(self, filename: str, password: bytes):
        with open(filename, 'rb') as f:
            pem = f.read()
        self._private_key = serialization.load_pem_private_key(pem, password=password)
        self._public_key = self._private_key.public_key()

    def get_public_key_compressed(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

    @staticmethod
    def generate_address(public_key_compressed: bytes) -> str:
        """Generates a P2PKH-style address from a compressed public key."""
        sha256_hash = hashlib.sha256(public_key_compressed).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
        versioned_hash = b'\x00' + ripemd160_hash # 0x00 for mainnet
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        binary_address = versioned_hash + checksum
        
        # Base58 encode
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        value = int.from_bytes(binary_address, 'big')
        encoded = ''
        while value > 0:
            value, remainder = divmod(value, 58)
            encoded = alphabet[remainder] + encoded
        
        # Prepend leading zeros
        for byte in binary_address:
            if byte == 0:
                encoded = '1' + encoded
            else:
                break
        return encoded

    def sign(self, data: bytes) -> bytes:
        """Signs data and returns the DER-encoded signature."""
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def verify(public_key_compressed: bytes, signature: bytes, data: bytes) -> bool:
        """Verifies a signature using a compressed public key."""
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_compressed)
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def aead_encrypt(self, plaintext: bytes, associated_data: bytes) -> Optional[bytes]:
        """Encrypts and authenticates data using AES-GCM."""
        if not self._net_key: return None
        aesgcm = AESGCM(self._net_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext # Nonce (12) + Ciphertext + Tag (16)

    def aead_decrypt(self, encrypted_packet: bytes, associated_data: bytes) -> Optional[bytes]:
        """Decrypts and verifies data using AES-GCM."""
        if not self._net_key: return None
        try:
            aesgcm = AESGCM(self._net_key)
            nonce = encrypted_packet[:12]
            ciphertext_with_tag = encrypted_packet[12:]
            return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            print("[CRYPTO] Decryption failed: Invalid authentication tag.")
            return None

# =============================================================================
# SESSION / HANDSHAKE (Ephemeral ECDH -> HKDF -> AES-GCM session)
# =============================================================================

def within_window(ts: int) -> bool:
    now = now_sec()
    return not (ts > now + RX_WINDOW_SEC or ts + RX_WINDOW_SEC < now)

def make_msg_nonce(prefix4: bytes, ts: int, seq: int) -> bytes:
    # 4B prefix | 4B seq | 4B ts = 12 bytes
    return prefix4 + struct.pack("!I", seq) + struct.pack("!I", ts)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def build_transcript(ver: int,
                     idA33: bytes, ephA33: bytes, nonceA12: bytes, tsA: int,
                     idB33: bytes, ephB33: bytes, nonceB12: bytes, tsB: int) -> bytes:
    # Mirror ESP32 layout (ver, tsA, idA, ephA, nonceA, tsB, idB, ephB, nonceB)
    return (
        struct.pack("!I", ver) +
        struct.pack("!I", tsA) + idA33 + ephA33 + nonceA12 +
        struct.pack("!I", tsB) + idB33 + ephB33 + nonceB12
    )

def pubkey_compressed_from_obj(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.X962,
                            format=serialization.PublicFormat.CompressedPoint)

def pubkey_from_compressed(pub33: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub33)

class Ephemeral:
    def __init__(self):
        self.priv: Optional[ec.EllipticCurvePrivateKey] = None
        self.pub33: Optional[bytes] = None
        self.nonce12: Optional[bytes] = None
        self.have = False

    def make(self):
        if self.have: return
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pub33 = pubkey_compressed_from_obj(self.priv.public_key())
        self.nonce12 = secrets.token_bytes(12)
        self.have = True

class Session:
    def __init__(self):
        self.established = False
        self.peer = (Config.ESP32_IP, Config.UDP_PORT)
        self.k_enc: Optional[bytes] = None
        self.k_mac: Optional[bytes] = None
        self.nonce_prefix4: Optional[bytes] = None
        self.rx_seq = 0
        self.tx_seq = 0
        self.last_rx_ts = 0
        self.peer_id_pub33: Optional[bytes] = None

g_eph = Ephemeral()
g_sess = Session()

def derive_session_keys(my_eph_priv: ec.EllipticCurvePrivateKey,
                        peer_eph33: bytes,
                        nonceA12: bytes, nonceB12: bytes,
                        my_id33: bytes, peer_id33: bytes) -> Tuple[bytes, bytes, bytes]:
    peer_pub = pubkey_from_compressed(peer_eph33)
    shared = my_eph_priv.exchange(ec.ECDH(), peer_pub)  # 32B
    salt = nonceA12 + nonceB12
    info = (b"SPACE-DOA v2\x00" + my_id33 + peer_id33 + g_eph.pub33 + peer_eph33)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info)
    okm = hkdf.derive(shared)  # 64 bytes
    k_enc = okm[:32]
    k_mac = okm[32:]
    nonce_prefix4 = secrets.token_bytes(4)
    return k_enc, k_mac, nonce_prefix4

def pack_header(type_id: int, seq: int) -> Tuple[bytes, int, int]:
    ts = now_sec()
    hdr = struct.pack(WIRE_STRUCT, PROTOCOL_VERSION, ts, seq, type_id)
    return hdr, ts, seq

def send_hello(sock: socket.socket):
    if not g_eph.have: g_eph.make()
    my_id33 = pubkey_compressed_from_obj(node.crypto._public_key)  # uses your identity key
    body = {
        "id": node.crypto.to_hex_bytes(my_id33),
        "eph": node.crypto.to_hex_bytes(g_eph.pub33),
        "na":  node.crypto.to_hex_bytes(g_eph.nonce12),
        "ts":  now_sec()
    }
    hdr, ts, _ = pack_header(MsgType.HELLO, 0)
    pkt = hdr + json.dumps(body, separators=(',', ':')).encode()
    sock.sendto(pkt, (Config.ESP32_IP, Config.UDP_PORT))
    node._last_hello_ts = ts
    # (ESP32 will reply with HELLO_ACK)

def send_hello_ack(sock: socket.socket, from_addr, peer_id33: bytes, peer_eph33: bytes, peer_nonceA12: bytes, tsA: int):
    if not g_eph.have: g_eph.make()
    my_id33 = pubkey_compressed_from_obj(node.crypto._public_key)
    k_enc, k_mac, nonce_prefix4 = derive_session_keys(g_eph.priv, peer_eph33, peer_nonceA12, g_eph.nonce12, my_id33, peer_id33)

    tsB = now_sec()
    transcript = build_transcript(PROTOCOL_VERSION, peer_id33, peer_eph33, peer_nonceA12, tsA,
                                  my_id33, g_eph.pub33, g_eph.nonce12, tsB)
    mac = hmac_sha256(k_mac, transcript)

    body = {
        "id": node.crypto.to_hex_bytes(my_id33),
        "eph": node.crypto.to_hex_bytes(g_eph.pub33),
        "nb":  node.crypto.to_hex_bytes(g_eph.nonce12),
        "np":  node.crypto.to_hex_bytes(nonce_prefix4),
        "mac": mac.hex(),
        "ts":  tsB
    }
    hdr, _, _ = pack_header(MsgType.HELLO_ACK, 0)
    pkt = hdr + json.dumps(body, separators=(',', ':')).encode()
    sock.sendto(pkt, from_addr)

    # Stage session (confirmed on first encrypted pkt)
    g_sess.established = True
    g_sess.peer = from_addr
    g_sess.k_enc = k_enc
    g_sess.k_mac = k_mac
    g_sess.nonce_prefix4 = nonce_prefix4
    g_sess.peer_id_pub33 = peer_id33
    g_sess.rx_seq = 0
    g_sess.tx_seq = 0
    g_sess.last_rx_ts = 0

# Convenience: hex<->bytes helpers onto CryptoLayer (non-breaking)
def _to_hex_bytes(b: bytes) -> str: return b.hex()
CryptoLayer.to_hex_bytes = staticmethod(_to_hex_bytes)

# =============================================================================
# HARDWARE LAYER
# =============================================================================

class Hardware:
    def __init__(self):
        self.i2c = None
        self.setup_gpio()
        self.setup_i2c()

    def setup_gpio(self):
        try:
            GPIO.setmode(GPIO.BCM)
            GPIO.setwarnings(False)
            for pin in [Config.LED_STATUS, Config.LED_TX, Config.LED_RX, Config.LED_ERROR]:
                GPIO.setup(pin, GPIO.OUT)
                GPIO.output(pin, GPIO.LOW)
            GPIO.output(Config.LED_STATUS, GPIO.HIGH) # Indicate boot
        except Exception as e:
            print(f"[HARDWARE] GPIO setup failed: {e}")

    def setup_i2c(self):
        try:
            self.i2c = smbus.SMBus(Config.I2C_BUS)
            # Wake up MPU6050/9250
            self.i2c.write_byte_data(Config.IMU_ADDRESS, 0x6B, 0x00)
            time.sleep(0.1)
        except Exception as e:
            print(f"[HARDWARE] I2C setup failed: {e}")
            self.i2c = None

    def read_sensors(self) -> Dict:
        """Reads sensor data with graceful error handling."""
        if not self.i2c:
            return {"error": "I2C not initialized"}
        try:
            # Read 16-bit word helper
            def read_word_2c(reg):
                high = self.i2c.read_byte_data(Config.IMU_ADDRESS, reg)
                low = self.i2c.read_byte_data(Config.IMU_ADDRESS, reg + 1)
                val = (high << 8) + low
                if val >= 0x8000:
                    return -((65535 - val) + 1)
                return val

            return {
                'accel_x': read_word_2c(0x3B) / 16384.0,
                'accel_y': read_word_2c(0x3D) / 16384.0,
                'accel_z': read_word_2c(0x3F) / 16384.0,
                'temp_c': (read_word_2c(0x41) / 340.0) + 36.53
            }
        except Exception as e:
            print(f"[HARDWARE] IMU read error: {e}")
            GPIO.output(Config.LED_ERROR, GPIO.HIGH)
            return {"error": str(e)}

    def cleanup(self):
        GPIO.cleanup()

# =============================================================================
# MAIN BLOCKCHAIN NODE CLASS
# =============================================================================

class BlockchainNode:
    def __init__(self):
        self.crypto = CryptoLayer()
        self.hardware = Hardware()

        self._bucket_tokens = Config.TOKEN_BUCKET_SIZE
        self._bucket_last = now_sec()
        self._sock = None  # filled by network_thread
        
        self.chain: List[Dict] = []
        self.mempool: List[Dict] = []
        self.utxo_set: Dict[str, UTXO] = {} # Key: "txid:index"
        
        self.node_lock = threading.Lock()
        self.msg_queue = queue.Queue()
        self.running = True

        # Rate Limiting
        self.token_bucket = Config.TOKEN_BUCKET_SIZE
        self.last_token_fill = now_sec()

    def bucket_allow(self) -> bool:
        nowt = now_sec()
        dt = nowt - self._bucket_last
        if dt > 0:
            self._bucket_tokens = min(
                Config.TOKEN_BUCKET_SIZE,
                self._bucket_tokens + dt * Config.TOKEN_BUCKET_RATE
            )
            self._bucket_last = nowt
        if self._bucket_tokens >= 1:
            self._bucket_tokens -= 1
            return True
        return False
    
    def initialize(self):
        """Initializes all components of the node."""
        self.crypto.initialize()
        self.load_blockchain_from_disk()
        
        if not self.chain:
            print("[CHAIN] No blockchain found. Creating genesis block...")
            self.create_genesis_block()
        
        self.rebuild_utxo_set()
        print(f"[CHAIN] Blockchain loaded. Height: {len(self.chain) - 1}. UTXOs: {len(self.utxo_set)}")
        GPIO.output(Config.LED_STATUS, GPIO.LOW) # Indicate ready

    def create_genesis_block(self):
        """Creates the very first block in the chain."""
        genesis_block = {
            "index": 0,
            "timestamp": 0,
            "transactions": [],
            "previous_hash": "0" * 64,
            "nonce": 0,
            "merkle_root": "0" * 64
        }
        genesis_block["hash"] = self.hash_block(genesis_block)
        self.chain.append(genesis_block)
        self.save_blockchain_to_disk()

    def rebuild_utxo_set(self):
        """Rebuilds the UTXO set from the entire blockchain."""
        print("[UTXO] Rebuilding UTXO set from chain...")
        self.utxo_set.clear()
        for block in self.chain:
            for tx in block['transactions']:
                txid = tx['txid']
                # Remove spent UTXOs
                if txid != "0"*64: # Not a coinbase transaction
                    for vin in tx['vin']:
                        utxo_key = f"{vin['txid']}:{vin['vout']}"
                        if utxo_key in self.utxo_set:
                            del self.utxo_set[utxo_key]
                # Add new UTXOs
                for i, vout in enumerate(tx['vout']):
                    utxo_key = f"{txid}:{i}"
                    self.utxo_set[utxo_key] = UTXO(txid, i, vout['amount'], vout['address'])
        print("[UTXO] Rebuild complete.")

    def network_thread(self):
        """Handles UDP I/O, handshake retries, ping, INV announcements, and rebroadcast."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((Config.UDP_IP, Config.UDP_PORT))
        print(f"[NET] UDP server listening on {Config.UDP_IP}:{Config.UDP_PORT}")

        self._last_hello_ms = 0
        self._last_ping_ms = 0
        self._last_mine_ts = now_sec()
        self._last_inv_ms = 0
        self._last_reb_ms = 0
        self._last_hello_ts = 0

        # Kick off HELLO proactively
        send_hello(self._sock)
        self._last_hello_ms = int(time.time() * 1000)

        while self.running:
            # 1) UDP pump once
            poll_udp_once(self._sock)

            # 2) Handshake retry
            now_ms = int(time.time() * 1000)
            if not g_sess.established and (now_ms - self._last_hello_ms) >= HELLO_RETRY_MS:
                send_hello(self._sock)
                self._last_hello_ms = now_ms

            # 3) Keep-alive ping
            if g_sess.established and (now_ms - self._last_ping_ms) >= PING_INTERVAL_MS:
                send_encrypted(self._sock, MsgType.PING, b'{"ping":1}')
                self._last_ping_ms = now_ms

            # 4) INV announce (share our tip)
            if g_sess.established and (now_ms - self._last_inv_ms) >= INV_ANNOUNCE_MS:
                tip = len(self.chain) - 1
                tip_hash = self.chain[-1]['hash'] if self.chain else "0" * 64
                body = json.dumps({"tip": tip, "hash": tip_hash}, separators=(',', ':')).encode()
                send_encrypted(self._sock, MsgType.INV, body)
                self._last_inv_ms = now_ms

            # 5) Mempool trickle rebroadcast
            if g_sess.established and (now_ms - self._last_reb_ms) >= REBROADCAST_MS:
                burst = 0
                for tx in list(self.mempool)[:REB_TX_BURST]:
                    send_encrypted(self._sock, MsgType.TX, json.dumps(tx, separators=(',', ':')).encode())
                    burst += 1
                    if burst >= REB_TX_BURST:
                        break
                self._last_reb_ms = now_ms

            time.sleep(0.005)

    def handle_block(self, b: Dict):
        """Validate and append a new block to the chain."""
        try:
            mrk = self.calculate_merkle_root(b['transactions'])
            if mrk != b['merkle_root']:
                print("[BLOCK] bad merkle"); return
            h2 = self.hash_block(b)
            if h2 != b.get('hash', ''):
                print("[BLOCK] bad header hash"); return
            if not b['hash'].startswith('0' * POW_ZEROS):
                print("[BLOCK] pow fail"); return
            if b['index'] != len(self.chain):
                print("[BLOCK] height mismatch"); return
            if b['index'] == 0:
                if b['previous_hash'] != "0" * 64:
                    print("[BLOCK] bad genesis prev"); return
            else:
                if b['previous_hash'] != self.chain[-1]['hash']:
                    print("[BLOCK] prev mismatch"); return

            self.chain.append(b)
            mined_ids = {tx['txid'] for tx in b['transactions'] if tx.get('txid')}
            self.mempool = [t for t in self.mempool if t['txid'] not in mined_ids]
            self.rebuild_utxo_set()
            self.save_blockchain_to_disk()
            GPIO.output(Config.LED_RX, GPIO.HIGH); GPIO.output(Config.LED_RX, GPIO.LOW)
            print(f"[BLOCK] accepted h={b['index']} {b['hash'][:10]}...")
        except Exception as e:
            print(f"[BLOCK] error: {e}")

    def process_inv(self, payload: Dict):
        """Handle peer inventory announcements (chain tip)."""
        peer_tip = int(payload.get("tip", 0))
        peer_hash = payload.get("hash", "0" * 64)
        my_tip = len(self.chain) - 1
        my_hash = self.chain[-1]['hash'] if self.chain else "0" * 64
        if peer_tip > my_tip:
            body = json.dumps({"from": my_tip, "count": 1}, separators=(',', ':')).encode()
            send_encrypted(self._sock, MsgType.GETBLOCK, body)
        elif peer_tip == my_tip and peer_hash != my_hash and my_tip > 0:
            body = json.dumps({"from": my_tip - 1, "count": 2}, separators=(',', ':')).encode()
            send_encrypted(self._sock, MsgType.GETBLOCK, body)

    def process_getblock(self, sender, payload: Dict):
        """Respond to GETBLOCK requests with serialized block data."""
        start = int(payload.get("from", 0))
        count = max(1, min(8, int(payload.get("count", 1))))
        tip = len(self.chain)
        for i in range(count):
            idx = start + i
            if idx >= tip:
                break
            block_bytes = json.dumps(self.chain[idx], separators=(',', ':')).encode()
            send_encrypted(self._sock, MsgType.BLOCK, block_bytes)

    def blockchain_thread(self):
        """Main blockchain loop: process queued messages and mine when due."""
        last_mine_ts = now_sec()
        while self.running:
            try:
                msg = self.msg_queue.get(timeout=0.5)
                t = msg['type']
                p = msg['payload']
                if t == MsgType.TX:
                    self.handle_transaction(p)
                elif t == MsgType.BLOCK:
                    self.handle_block(p)
                elif t == MsgType.INV:
                    self.process_inv(p)
                elif t == MsgType.GETBLOCK:
                    self.process_getblock(msg['sender'], p)
                elif t == MsgType.PING:
                    send_encrypted(self._sock, MsgType.PONG, json.dumps({"pong": 1}).encode())
            except queue.Empty:
                # Miner cadence (time or mempool pressure)
                nowt = now_sec()
                due_time = (nowt - last_mine_ts) >= MINE_INTERVAL_SEC
                due_pressure = len(self.mempool) >= MEMPOOL_MINE_MIN
                if due_time or due_pressure:
                    self.attempt_mining()
                    last_mine_ts = nowt
                continue

    def broadcast_message(self, type_id: int, payload: Dict):
        """Encrypts and broadcasts to the current session peer (used by miner, etc.)."""
        try:
            if not self._sock:
                print("[NET] No socket; not sending.")
                return
            payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            ok = send_encrypted(self._sock, type_id, payload_bytes)
            if ok:
                print(f"[NET] Encrypted send type {type_id} -> {g_sess.peer}")
        except Exception as e:
            print(f"[NET] Broadcast error: {e}")


def process_hello(from_addr, body: bytes):
    try:
        d = json.loads(body.decode())
        idhex, ephhex, nhex, tsA = d.get("id"), d.get("eph"), d.get("na"), d.get("ts")
        if not (idhex and ephhex and nhex and tsA): return
        if not within_window(int(tsA)): return
        peer_id33   = from_hex(idhex)
        peer_eph33  = from_hex(ephhex)
        peer_nonceA = from_hex(nhex)
        # (Optionally check allowlist of peer identity here)
        send_hello_ack(node._sock, from_addr, peer_id33, peer_eph33, peer_nonceA, int(tsA))
    except Exception as e:
        print(f"[HELLO] parse error: {e}")

def process_hello_ack(from_addr, body: bytes):
    try:
        if not g_eph.have: return
        d = json.loads(body.decode())
        idhex, ephhex, nbhex, nphx, machex, tsB = d.get("id"), d.get("eph"), d.get("nb"), d.get("np"), d.get("mac"), d.get("ts")
        if not (idhex and ephhex and nbhex and machex and nphx and tsB): return
        if not within_window(int(tsB)): return

        peer_id33  = from_hex(idhex)
        peer_eph33 = from_hex(ephhex)
        nonceB     = from_hex(nbhex)
        mac_recv   = from_hex(machex)
        nonce_pref = from_hex(nphx)

        my_id33 = pubkey_compressed_from_obj(node.crypto._public_key)
        k_enc, k_mac, _junk = derive_session_keys(g_eph.priv, peer_eph33, g_eph.nonce12, nonceB, my_id33, peer_id33)
        transcript = build_transcript(PROTOCOL_VERSION,
                                      my_id33, g_eph.pub33, g_eph.nonce12, node._last_hello_ts,
                                      peer_id33, peer_eph33, nonceB, int(tsB))
        mac_calc = hmac_sha256(k_mac, transcript)
        if not constant_time.bytes_eq(mac_calc, mac_recv):
            print("[HELLO_ACK] MAC verify failed"); return

        g_sess.established = True
        g_sess.peer = from_addr
        g_sess.k_enc = k_enc
        g_sess.k_mac = k_mac
        g_sess.nonce_prefix4 = nonce_pref
        g_sess.peer_id_pub33 = peer_id33
        g_sess.rx_seq = 0
        g_sess.tx_seq = 0
        g_sess.last_rx_ts = 0
        print("[SESSION] established")
    except Exception as e:
        print(f"[HELLO_ACK] error: {e}")

def poll_udp_once(sock: socket.socket):
    # Non-blocking check
    sock.settimeout(0.05)
    try:
        data, addr = sock.recvfrom(MAX_MSG_SIZE)
    except socket.timeout:
        return
    except Exception as e:
        print(f"[NET] recv error: {e}")
        return

    # Basic token bucket (reuse your fields)
    if not node.bucket_allow():
        print(f"[NET] Rate limit exceeded for {addr}. Packet dropped.")
        return

    # Peek header quickly
    if len(data) < WIRE_HDR_LEN:
        return
    ver, ts, seq, type_id = struct.unpack(WIRE_STRUCT, data[:WIRE_HDR_LEN])

    if type_id == MsgType.HELLO:
        process_hello(addr, data[WIRE_HDR_LEN:])
        return
    if type_id == MsgType.HELLO_ACK:
        process_hello_ack(addr, data[WIRE_HDR_LEN:])
        return

    if not g_sess.established:
        return

    out = recv_encrypted(data)
    if not out:
        return
    _, pt, _ = out
    try:
        message = json.loads(pt.decode())
        node.msg_queue.put({"type": type_id, "payload": message, "sender": addr})
    except Exception as e:
        print(f"[NET] payload parse error: {e}")

    def handle_transaction(self, tx: Dict):
        """Validates and adds a transaction to the mempool."""
        with self.node_lock:
            if not self.validate_transaction(tx):
                print(f"[CHAIN] Invalid transaction {tx['txid'][:10]}... received.")
                return
            
            # Check for duplicates
            if any(t['txid'] == tx['txid'] for t in self.mempool):
                return

            self.mempool.append(tx)
            print(f"[MEMPOOL] Added transaction {tx['txid'][:10]}... | Size: {len(self.mempool)}")

    def validate_transaction(self, tx: Dict, check_utxo=True) -> bool:
        """Full validation of a transaction."""
        # 1. Verify signature
        tx_copy = tx.copy()
        signature = from_hex(tx_copy.pop('signature'))
        tx_copy.pop('txid') # txid is not part of the signed data
        
        # Create a deterministic string to sign/verify
        signed_data = json.dumps(tx_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        if not self.crypto.verify(from_hex(tx['from_pubkey']), signature, signed_data):
            print("[VALIDATE] Signature verification failed.")
            return False

        if not check_utxo: return True

        # 2. Check inputs and UTXOs
        total_in = 0
        for vin in tx['vin']:
            utxo_key = f"{vin['txid']}:{vin['vout']}"
            if utxo_key not in self.utxo_set:
                print(f"[VALIDATE] Input UTXO not found: {utxo_key}")
                return False
            
            utxo = self.utxo_set[utxo_key]
            # Check if the sender's address matches the UTXO's address
            expected_address = self.crypto.generate_address(from_hex(tx['from_pubkey']))
            if utxo.address != expected_address:
                print(f"[VALIDATE] Address mismatch for UTXO {utxo_key}")
                return False
            
            total_in += utxo.amount
        
        # 3. Check outputs
        total_out = sum(vout['amount'] for vout in tx['vout'])
        
        if total_in < total_out:
            print(f"[VALIDATE] Insufficient funds: IN={total_in}, OUT={total_out}")
            return False
            
        return True

    def attempt_mining(self):
        """Mines a new block if there are transactions in the mempool."""
        with self.node_lock:
            if not self.mempool:
                return

            print(f"[MINING] Attempting to mine a new block with {len(self.mempool)} transactions...")
            
            # Select transactions for the new block
            transactions_to_mine = self.mempool[:Config.MAX_TX_PER_BLOCK]
            
            # Add coinbase transaction
            coinbase_tx = self.create_coinbase_transaction(transactions_to_mine)
            
            block_transactions = [coinbase_tx] + transactions_to_mine
            
            # Create the block
            previous_block = self.chain[-1]
            new_block = {
                "index": previous_block['index'] + 1,
                "timestamp": now_sec(),
                "transactions": block_transactions,
                "previous_hash": previous_block['hash'],
                "merkle_root": self.calculate_merkle_root(block_transactions),
                "nonce": 0
            }

            # Proof of Work
            target = '0' * Config.DIFFICULTY_LEADING_ZEROES
            while True:
                block_hash = self.hash_block(new_block)
                if block_hash.startswith(target):
                    new_block['hash'] = block_hash
                    break
                new_block['nonce'] += 1

            print(f"[MINING] Block {new_block['index']} mined! Hash: {new_block['hash'][:10]}...")
            
            # Add to chain and update state
            self.chain.append(new_block)
            self.mempool = self.mempool[Config.MAX_TX_PER_BLOCK:]
            self.rebuild_utxo_set() # Easiest way to update UTXOs after a block
            self.save_blockchain_to_disk()
            
            # Broadcast the new block
            self.broadcast_message(MsgType.BLOCK, new_block)

    def create_coinbase_transaction(self, block_txs: List[Dict]) -> Dict:
        """Creates the coinbase transaction that awards the miner."""
        tx_fees = sum(tx['fee'] for tx in block_txs)
        total_reward = Config.BLOCK_REWARD + tx_fees
        
        coinbase = {
            "txid": "0" * 64,
            "vin": [{"txid": "0"*64, "vout": -1}],
            "vout": [{"amount": total_reward, "address": self.crypto.address}],
            # No signature needed for coinbase
        }
        return coinbase

    @staticmethod
    def hash_block(block: Dict) -> str:
        """Hashes a block header."""
        header_string = json.dumps({
            "index": block['index'],
            "timestamp": block['timestamp'],
            "previous_hash": block['previous_hash'],
            "merkle_root": block['merkle_root'],
            "nonce": block['nonce']
        }, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(header_string).hexdigest()

    @staticmethod
    def calculate_merkle_root(transactions: List[Dict]) -> str:
        """Calculates the Merkle root of a list of transactions."""
        if not transactions:
            return "0" * 64
        
        txids = [tx['txid'] for tx in transactions]
        
        while len(txids) > 1:
            if len(txids) % 2 != 0:
                txids.append(txids[-1]) # Duplicate last hash if odd
            
            new_level = []
            for i in range(0, len(txids), 2):
                combined = (txids[i] + txids[i+1]).encode('utf-8')
                new_level.append(hashlib.sha256(combined).hexdigest())
            txids = new_level
            
        return txids[0]

def send_encrypted(sock: socket.socket, type_id: int, payload_bytes: bytes) -> bool:
    if not g_sess.established or not g_sess.k_enc:
        return False
    if not node.bucket_allow():  # token bucket on the node
        print("[RATE] drop (bucket)")
        return False

    g_sess.tx_seq += 1
    hdr, ts, seq = pack_header(type_id, g_sess.tx_seq)
    nonce = make_msg_nonce(g_sess.nonce_prefix4, ts, seq)

    aes = AESGCM(g_sess.k_enc)
    ct = aes.encrypt(nonce, payload_bytes, hdr)  # AAD = header
    pkt = hdr + ct
    sock.sendto(pkt, g_sess.peer)
    GPIO.output(Config.LED_TX, GPIO.HIGH); GPIO.output(Config.LED_TX, GPIO.LOW)
    return True


def recv_encrypted(pkt: bytes) -> Optional[Tuple[int, bytes, Tuple[str,int]]]:
    if len(pkt) < WIRE_HDR_LEN + 16: return None
    ver, ts, seq, type_id = struct.unpack(WIRE_STRUCT, pkt[:WIRE_HDR_LEN])
    if ver != PROTOCOL_VERSION or not within_window(ts): return None
    if not g_sess.established or not g_sess.k_enc or not g_sess.nonce_prefix4: return None

    # replay/order defense
    if seq <= g_sess.rx_seq and ts <= g_sess.last_rx_ts:
        return None

    hdr = pkt[:WIRE_HDR_LEN]
    ct  = pkt[WIRE_HDR_LEN:]
    nonce = make_msg_nonce(g_sess.nonce_prefix4, ts, seq)
    aes = AESGCM(g_sess.k_enc)
    try:
        pt = aes.decrypt(nonce, ct, hdr)
    except InvalidTag:
        return None

    g_sess.rx_seq = seq
    g_sess.last_rx_ts = ts
    return (type_id, pt, None)


def save_blockchain_to_disk(self):
        """Saves the blockchain to disk using an atomic write."""
        temp_file = Config.CHAIN_FILE + ".tmp"
        with self.node_lock:
            with open(temp_file, 'w') as f:
                json.dump({"chain": self.chain}, f)
            os.rename(temp_file, Config.CHAIN_FILE)

def load_blockchain_from_disk(self):
        """Loads the blockchain from disk."""
        if os.path.exists(Config.CHAIN_FILE):
            with open(Config.CHAIN_FILE, 'r') as f:
                data = json.load(f)
                self.chain = data['chain']

def run(self):
        """Starts all node threads and runs forever."""
        self.initialize()
        
        threads = [
            threading.Thread(target=self.network_thread, daemon=True),
            threading.Thread(target=self.blockchain_thread, daemon=True)
        ]
        for t in threads:
            t.start()
            
        print("[SYSTEM] All threads started. Node is operational.")
        
        try:
            while self.running:
                # Main thread can be used for a CLI or other top-level tasks
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[SYSTEM] Shutdown signal received.")
            self.running = False
            self.hardware.cleanup()
            print("[SYSTEM] Node stopped.")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    node = BlockchainNode()
    node.run()
