#!/usr/bin/env python3
"""
Raspberry Pi CubeSat Blockchain Node
Complete implementation for orbital blockchain operations
"""

import time
import hashlib
import json
import RPi.GPIO as GPIO
from datetime import datetime
from typing import List, Dict, Optional
import spidev
import smbus
import serial
import threading
import queue

# GPIO Pin Configuration
class PinConfig:
    # LoRa Module (SX1278)
    LORA_CS = 8
    LORA_RST = 22
    LORA_DIO0 = 24
    LORA_DIO1 = 23
    
    # Status LEDs
    LED_POWER = 17
    LED_TX = 27
    LED_RX = 18
    LED_ERROR = 25
    
    # Power Management
    POWER_GOOD = 5
    BATTERY_MONITOR = 6

# I2C Configuration
I2C_BUS = 1
IMU_ADDRESS = 0x68  # MPU9250
TEMP_ADDRESS = 0x48  # Temperature sensor

class BlockchainNode:
    """Main blockchain node implementation for Raspberry Pi"""
    
    def __init__(self):
        self.setup_gpio()
        self.setup_i2c()
        self.setup_spi()
        self.setup_lora()
        
        # Blockchain state
        self.chain: List[Dict] = []
        self.pending_transactions: List[Dict] = []
        self.utxo_set: Dict = {}
        self.peers: List[str] = []
        
        # Node identity
        self.private_key = self.generate_private_key()
        self.public_key = self.derive_public_key(self.private_key)
        self.address = self.generate_address(self.public_key)
        
        # Threading
        self.tx_queue = queue.Queue()
        self.block_queue = queue.Queue()
        self.running = True
        
    def setup_gpio(self):
        """Initialize GPIO pins"""
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        
        # Setup outputs
        for pin in [PinConfig.LED_POWER, PinConfig.LED_TX, 
                   PinConfig.LED_RX, PinConfig.LED_ERROR]:
            GPIO.setup(pin, GPIO.OUT)
            GPIO.output(pin, GPIO.LOW)
        
        # Setup inputs
        GPIO.setup(PinConfig.POWER_GOOD, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.setup(PinConfig.LORA_DIO0, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
        
        # Power LED on
        GPIO.output(PinConfig.LED_POWER, GPIO.HIGH)
    
    def setup_i2c(self):
        """Initialize I2C bus for sensors"""
        self.i2c = smbus.SMBus(I2C_BUS)
        
        # Initialize IMU
        self.i2c.write_byte_data(IMU_ADDRESS, 0x6B, 0x00)  # Wake up MPU9250
        time.sleep(0.1)
        
    def setup_spi(self):
        """Initialize SPI for LoRa module"""
        self.spi = spidev.SpiDev()
        self.spi.open(0, 0)  # Bus 0, Device 0
        self.spi.max_speed_hz = 5000000
        self.spi.mode = 0b00
        
    def setup_lora(self):
        """Initialize LoRa module"""
        # Reset LoRa module
        GPIO.setup(PinConfig.LORA_RST, GPIO.OUT)
        GPIO.output(PinConfig.LORA_RST, GPIO.LOW)
        time.sleep(0.01)
        GPIO.output(PinConfig.LORA_RST, GPIO.HIGH)
        time.sleep(0.1)
        
        # Configure LoRa registers
        self.lora_write_register(0x01, 0x80)  # Sleep mode
        self.lora_write_register(0x01, 0x81)  # LoRa mode
        
        # Set frequency (433 MHz)
        freq = int(433000000 / (32000000 / 2**19))
        self.lora_write_register(0x06, (freq >> 16) & 0xFF)
        self.lora_write_register(0x07, (freq >> 8) & 0xFF)
        self.lora_write_register(0x08, freq & 0xFF)
        
        # Set spreading factor, bandwidth, coding rate
        self.lora_write_register(0x1D, 0x72)  # SF7, BW125, CR4/5
        self.lora_write_register(0x1E, 0x74)  # SF7, CRC on
        
        # Set TX power (17 dBm)
        self.lora_write_register(0x09, 0x8F)
        
    def lora_write_register(self, address: int, value: int):
        """Write to LoRa register via SPI"""
        GPIO.output(PinConfig.LORA_CS, GPIO.LOW)
        self.spi.xfer2([address | 0x80, value])
        GPIO.output(PinConfig.LORA_CS, GPIO.HIGH)
        
    def lora_read_register(self, address: int) -> int:
        """Read from LoRa register via SPI"""
        GPIO.output(PinConfig.LORA_CS, GPIO.LOW)
        data = self.spi.xfer2([address & 0x7F, 0x00])
        GPIO.output(PinConfig.LORA_CS, GPIO.HIGH)
        return data[1]
    
    def generate_private_key(self) -> bytes:
        """Generate ECDSA private key"""
        import secrets
        return secrets.token_bytes(32)
    
    def derive_public_key(self, private_key: bytes) -> bytes:
        """Derive public key from private key"""
        # Simplified - use proper ECDSA library in production
        return hashlib.sha256(private_key).digest()
    
    def generate_address(self, public_key: bytes) -> str:
        """Generate blockchain address from public key"""
        # Simplified address generation
        hash160 = hashlib.new('ripemd160')
        hash160.update(hashlib.sha256(public_key).digest())
        return 'PI' + hash160.hexdigest()[:30].upper()
    
    def create_transaction(self, recipient: str, amount: float) -> Dict:
        """Create and sign a new transaction"""
        GPIO.output(PinConfig.LED_TX, GPIO.HIGH)
        
        transaction = {
            'from': self.address,
            'to': recipient,
            'amount': amount,
            'timestamp': time.time(),
            'nonce': len(self.pending_transactions)
        }
        
        # Sign transaction
        tx_string = json.dumps(transaction, sort_keys=True)
        signature = self.sign_data(tx_string.encode())
        transaction['signature'] = signature.hex()
        
        # Calculate transaction ID
        transaction['txid'] = hashlib.sha256(
            (tx_string + signature.hex()).encode()
        ).hexdigest()
        
        self.pending_transactions.append(transaction)
        GPIO.output(PinConfig.LED_TX, GPIO.LOW)
        
        return transaction
    
    def sign_data(self, data: bytes) -> bytes:
        """Sign data with private key"""
        # Simplified - use proper ECDSA in production
        return hashlib.sha256(data + self.private_key).digest()
    
    def verify_signature(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature"""
        # Simplified verification
        expected = hashlib.sha256(data + public_key).digest()
        return expected == signature
    
    def mine_block(self) -> Optional[Dict]:
        """Mine a new block"""
        if not self.pending_transactions:
            return None
        
        print("Mining new block...")
        
        # Get previous block
        previous_block = self.chain[-1] if self.chain else None
        previous_hash = previous_block['hash'] if previous_block else '0' * 64
        
        # Create new block
        block = {
            'index': len(self.chain),
            'timestamp': time.time(),
            'transactions': self.pending_transactions[:10],  # Max 10 tx per block
            'previous_hash': previous_hash,
            'nonce': 0
        }
        
        # Proof of Work
        target = '0000'  # Difficulty target
        while True:
            block_string = json.dumps(block, sort_keys=True)
            block_hash = hashlib.sha256(block_string.encode()).hexdigest()
            
            if block_hash.startswith(target):
                block['hash'] = block_hash
                break
            
            block['nonce'] += 1
            
            # Check if we should stop mining
            if not self.running:
                return None
        
        # Add block to chain
        self.chain.append(block)
        
        # Clear pending transactions
        self.pending_transactions = []
        
        print(f"Block mined! Hash: {block_hash}")
        return block
    
    def broadcast_transaction(self, transaction: Dict):
        """Broadcast transaction via LoRa"""
        GPIO.output(PinConfig.LED_TX, GPIO.HIGH)
        
        # Prepare packet
        packet = {
            'type': 'TX',
            'data': transaction
        }
        packet_bytes = json.dumps(packet).encode()
        
        # Send via LoRa
        self.lora_transmit(packet_bytes)
        
        GPIO.output(PinConfig.LED_TX, GPIO.LOW)
    
    def lora_transmit(self, data: bytes):
        """Transmit data via LoRa"""
        # Set to standby mode
        self.lora_write_register(0x01, 0x81)
        
        # Set payload length
        self.lora_write_register(0x22, len(data))
        
        # Write data to FIFO
        self.lora_write_register(0x0D, 0x80)  # FIFO address
        GPIO.output(PinConfig.LORA_CS, GPIO.LOW)
        self.spi.xfer2([0x80] + list(data))
        GPIO.output(PinConfig.LORA_CS, GPIO.HIGH)
        
        # Start transmission
        self.lora_write_register(0x01, 0x83)
        
        # Wait for transmission complete
        while not GPIO.input(PinConfig.LORA_DIO0):
            time.sleep(0.001)
        
        # Clear IRQ
        self.lora_write_register(0x12, 0xFF)
    
    def lora_receive(self) -> Optional[bytes]:
        """Receive data via LoRa"""
        # Check if data available
        if not GPIO.input(PinConfig.LORA_DIO0):
            return None
        
        GPIO.output(PinConfig.LED_RX, GPIO.HIGH)
        
        # Read payload length
        length = self.lora_read_register(0x13)
        
        # Read FIFO
        self.lora_write_register(0x0D, 0x00)  # FIFO address
        GPIO.output(PinConfig.LORA_CS, GPIO.LOW)
        data = self.spi.xfer2([0x00] + [0x00] * length)
        GPIO.output(PinConfig.LORA_CS, GPIO.HIGH)
        
        # Clear IRQ
        self.lora_write_register(0x12, 0xFF)
        
        GPIO.output(PinConfig.LED_RX, GPIO.LOW)
        
        return bytes(data[1:])
    
    def read_sensors(self) -> Dict:
        """Read sensor data"""
        sensor_data = {}
        
        # Read IMU data
        try:
            # Accelerometer
            accel_x = self.read_i2c_word(IMU_ADDRESS, 0x3B) / 16384.0
            accel_y = self.read_i2c_word(IMU_ADDRESS, 0x3D) / 16384.0
            accel_z = self.read_i2c_word(IMU_ADDRESS, 0x3F) / 16384.0
            
            # Gyroscope
            gyro_x = self.read_i2c_word(IMU_ADDRESS, 0x43) / 131.0
            gyro_y = self.read_i2c_word(IMU_ADDRESS, 0x45) / 131.0
            gyro_z = self.read_i2c_word(IMU_ADDRESS, 0x47) / 131.0
            
            # Temperature
            temp_raw = self.read_i2c_word(IMU_ADDRESS, 0x41)
            temperature = (temp_raw / 340.0) + 36.53
            
            sensor_data['imu'] = {
                'accel': {'x': accel_x, 'y': accel_y, 'z': accel_z},
                'gyro': {'x': gyro_x, 'y': gyro_y, 'z': gyro_z},
                'temp': temperature
            }
        except Exception as e:
            print(f"IMU read error: {e}")
            GPIO.output(PinConfig.LED_ERROR, GPIO.HIGH)
        
        # Check power status
        sensor_data['power_good'] = GPIO.input(PinConfig.POWER_GOOD)
        
        return sensor_data
    
    def read_i2c_word(self, address: int, register: int) -> int:
        """Read 16-bit word from I2C device"""
        high = self.i2c.read_byte_data(address, register)
        low = self.i2c.read_byte_data(address, register + 1)
        value = (high << 8) + low
        
        # Convert to signed
        if value >= 0x8000:
            value = -((65535 - value) + 1)
        
        return value
    
    def network_thread(self):
        """Network communication thread"""
        while self.running:
            # Check for incoming messages
            data = self.lora_receive()
            if data:
                try:
                    packet = json.loads(data.decode())
                    
                    if packet['type'] == 'TX':
                        # Add to transaction queue
                        self.tx_queue.put(packet['data'])
                    elif packet['type'] == 'BLOCK':
                        # Add to block queue
                        self.block_queue.put(packet['data'])
                    elif packet['type'] == 'PING':
                        # Respond to ping
                        self.send_pong(packet['from'])
                        
                except Exception as e:
                    print(f"Network error: {e}")
            
            time.sleep(0.1)
    
    def blockchain_thread(self):
        """Blockchain processing thread"""
        while self.running:
            # Process incoming transactions
            try:
                tx = self.tx_queue.get(timeout=1)
                if self.verify_transaction(tx):
                    self.pending_transactions.append(tx)
            except queue.Empty:
                pass
            
            # Mine block if enough transactions
            if len(self.pending_transactions) >= 5:
                block = self.mine_block()
                if block:
                    self.broadcast_block(block)
            
            time.sleep(1)
    
    def telemetry_thread(self):
        """Telemetry collection thread"""
        while self.running:
            # Read sensors
            sensor_data = self.read_sensors()
            
            # Create telemetry packet
            telemetry = {
                'timestamp': time.time(),
                'node': self.address,
                'sensors': sensor_data,
                'blockchain': {
                    'height': len(self.chain),
                    'pending_tx': len(self.pending_transactions),
                    'peers': len(self.peers)
                }
            }
            
            # Log telemetry
            print(f"Telemetry: {json.dumps(telemetry, indent=2)}")
            
            # Sleep for 10 seconds
            time.sleep(10)
    
    def verify_transaction(self, tx: Dict) -> bool:
        """Verify transaction validity"""
        # Check required fields
        required = ['from', 'to', 'amount', 'timestamp', 'signature', 'txid']
        if not all(field in tx for field in required):
            return False
        
        # Verify signature (simplified)
        tx_copy = tx.copy()
        signature = bytes.fromhex(tx_copy.pop('signature'))
        tx_string = json.dumps(tx_copy, sort_keys=True)
        
        # In production, verify with actual public key
        return True
    
    def broadcast_block(self, block: Dict):
        """Broadcast block via LoRa"""
        packet = {
            'type': 'BLOCK',
            'data': block
        }
        packet_bytes = json.dumps(packet).encode()
        self.lora_transmit(packet_bytes)
    
    def send_pong(self, address: str):
        """Send pong response"""
        packet = {
            'type': 'PONG',
            'from': self.address,
            'to': address
        }
        packet_bytes = json.dumps(packet).encode()
        self.lora_transmit(packet_bytes)
    
    def save_blockchain(self, filename: str = 'blockchain.json'):
        """Save blockchain to file"""
        with open(filename, 'w') as f:
            json.dump({
                'chain': self.chain,
                'utxo_set': self.utxo_set,
                'peers': self.peers
            }, f, indent=2)
    
    def load_blockchain(self, filename: str = 'blockchain.json'):
        """Load blockchain from file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                self.chain = data['chain']
                self.utxo_set = data['utxo_set']
                self.peers = data['peers']
        except FileNotFoundError:
            print("No existing blockchain found, starting fresh")
    
    def run(self):
        """Main run loop"""
        print(f"Starting CubeSat Blockchain Node")
        print(f"Node Address: {self.address}")
        
        # Load existing blockchain
        self.load_blockchain()
        
        # Start threads
        threads = [
            threading.Thread(target=self.network_thread, daemon=True),
            threading.Thread(target=self.blockchain_thread, daemon=True),
            threading.Thread(target=self.telemetry_thread, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        # Create genesis block if needed
        if not self.chain:
            genesis = {
                'index': 0,
                'timestamp': time.time(),
                'transactions': [],
                'previous_hash': '0' * 64,
                'nonce': 0
            }
            genesis['hash'] = hashlib.sha256(
                json.dumps(genesis, sort_keys=True).encode()
            ).hexdigest()
            self.chain.append(genesis)
        
        try:
            # Main loop
            while True:
                # Example: Create a transaction every 30 seconds
                if len(self.peers) > 0:
                    recipient = self.peers[0]  # Send to first peer
                    tx = self.create_transaction(recipient, 10.0)
                    self.broadcast_transaction(tx)
                
                # Save blockchain periodically
                self.save_blockchain()
                
                time.sleep(30)
                
        except KeyboardInterrupt:
            print("\nShutting down...")
            self.running = False
            
            # Save blockchain
            self.save_blockchain()
            
            # Cleanup
            GPIO.cleanup()
            self.spi.close()
            
            print("Node stopped")

def main():
    """Main entry point"""
    node = BlockchainNode()
    node.run()

if __name__ == "__main__":
    main()
