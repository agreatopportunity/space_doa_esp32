#!/usr/bin/env python3
"""
SPACE DOA - Raspberry Pi CubeSat Blockchain Node
Production-Ready Implementation v3.0.0

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

# =============================================================================
# UTILITY & DATA STRUCTURES
# =============================================================================

def now_sec() -> int:
    """Returns the current time as monotonic seconds."""
    return int(time.monotonic())

def to_hex(data: bytes) -> str:
    return data.hex()

def from_hex(data_str: str) -> bytes:
    return bytes.fromhex(data_str)

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
        
        self.chain: List[Dict] = []
        self.mempool: List[Dict] = []
        self.utxo_set: Dict[str, UTXO] = {} # Key: "txid:index"
        
        self.node_lock = threading.Lock()
        self.msg_queue = queue.Queue()
        self.running = True

        # Rate Limiting
        self.token_bucket = Config.TOKEN_BUCKET_SIZE
        self.last_token_fill = now_sec()

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
        """Handles UDP communication for receiving messages."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((Config.UDP_IP, Config.UDP_PORT))
        print(f"[NET] UDP server listening on {Config.UDP_IP}:{Config.UDP_PORT}")

        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                GPIO.output(Config.LED_RX, GPIO.HIGH)
                
                # --- Rate Limiting ---
                current_time = now_sec()
                time_passed = current_time - self.last_token_fill
                self.token_bucket += time_passed * Config.TOKEN_BUCKET_RATE
                if self.token_bucket > Config.TOKEN_BUCKET_SIZE:
                    self.token_bucket = Config.TOKEN_BUCKET_SIZE
                self.last_token_fill = current_time

                if self.token_bucket < 1:
                    print(f"[NET] Rate limit exceeded for {addr}. Packet dropped.")
                    continue
                self.token_bucket -= 1

                # --- Protocol Deserialization ---
                if len(data) < 13: continue # Header is 13 bytes
                ver, ts, seq, type_id = struct.unpack('!IIIB', data[:13])
                
                if ver != Config.PROTOCOL_VERSION: continue

                if not (now_sec() - Config.RX_WINDOW_SEC <= ts <= now_sec() + Config.RX_WINDOW_SEC):
                    print(f"[NET] Stale packet from {addr}. Dropped.")
                    continue
                    
                # --- Decryption ---
                header = data[:13]
                encrypted_payload = data[13:]
                payload = self.crypto.aead_decrypt(encrypted_payload, header)

                if payload:
                    message = json.loads(payload.decode())
                    self.msg_queue.put({"type": type_id, "payload": message, "sender": addr})

                GPIO.output(Config.LED_RX, GPIO.LOW)
            except Exception as e:
                print(f"[NET] Network thread error: {e}")

    def blockchain_thread(self):
        """Main thread for processing messages and managing the blockchain."""
        while self.running:
            try:
                msg = self.msg_queue.get(timeout=1)
                
                if msg['type'] == 1: # Transaction
                    self.handle_transaction(msg['payload'])
                elif msg['type'] == 2: # Block
                    self.handle_block(msg['payload'])
                # Add handlers for PING, etc.

            except queue.Empty:
                # No messages, try to mine a block
                self.attempt_mining()
                continue

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
            self.broadcast_message(2, new_block)

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

    def broadcast_message(self, type_id: int, payload: Dict):
        """Encrypts and broadcasts a message to known peers (ESP32)."""
        try:
            GPIO.output(Config.LED_TX, GPIO.HIGH)
            payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            header = struct.pack('!IIIB', Config.PROTOCOL_VERSION, now_sec(), 0, type_id) # Seq 0 for now
            
            encrypted_packet = self.crypto.aead_encrypt(payload_bytes, header)
            
            if encrypted_packet:
                full_packet = header + encrypted_packet
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(full_packet, (Config.ESP32_IP, Config.UDP_PORT))
                print(f"[NET] Broadcasted message type {type_id} to {Config.ESP32_IP}")
        except Exception as e:
            print(f"[NET] Broadcast error: {e}")
        finally:
            GPIO.output(Config.LED_TX, GPIO.LOW)

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
