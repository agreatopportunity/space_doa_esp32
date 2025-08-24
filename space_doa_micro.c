/**
 * SPACE DOA - CubeSat Blockchain Controller
 * ESP32 Implementation for Orbital Distributed Ledger
 * Version: 1.0.0
 * 
 * Hardware Requirements:
 * - ESP32 DevKit (ESP32-WROOM-32)
 * - LoRa Module (SX1276/SX1278) - Optional
 * - MPU6050 IMU - Optional
 * - SD Card Module - Optional
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include <EEPROM.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecdsa.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

// Pin Definitions
#define LED_STATUS 2
#define LED_TX 4
#define LED_RX 5
#define LORA_CS 15
#define LORA_RST 14
#define LORA_DIO0 26
#define SD_CS 13
#define IMU_SDA 21
#define IMU_SCL 22

// Network Configuration
const char* WIFI_SSID = "CUBESAT_GROUND";
const char* WIFI_PASS = "blockchain2024";
const int UDP_PORT = 8888;

// Blockchain Configuration
#define MAX_TRANSACTIONS 100
#define MAX_BLOCKS 1000
#define BLOCK_SIZE 10  // transactions per block
#define DIFFICULTY 4   // leading zeros in hash

// Memory Management
#define HEAP_SIZE 32768
#define STACK_SIZE 4096

// ==================== Data Structures ====================

struct Transaction {
    char from[35];
    char to[35];
    uint32_t amount;
    uint32_t timestamp;
    uint32_t nonce;
    char signature[65];
    char txid[65];
};

struct Block {
    uint32_t index;
    uint32_t timestamp;
    char prevHash[65];
    char merkleRoot[65];
    uint32_t nonce;
    uint8_t txCount;
    Transaction transactions[BLOCK_SIZE];
    char hash[65];
};

struct UTXOEntry {
    char txid[65];
    uint32_t vout;
    char address[35];
    uint32_t amount;
    bool spent;
};

class BlockchainNode {
private:
    // Blockchain state
    Block* chain;
    uint16_t chainLength;
    Transaction* mempool;
    uint16_t mempoolSize;
    UTXOEntry* utxoSet;
    uint16_t utxoCount;
    
    // Node identity
    uint8_t privateKey[32];
    uint8_t publicKey[33];
    char address[35];
    uint32_t balance;
    
    // Network
    WiFiUDP udp;
    IPAddress peers[10];
    uint8_t peerCount;
    
    // Thread synchronization
    SemaphoreHandle_t chainMutex;
    SemaphoreHandle_t mempoolMutex;
    QueueHandle_t txQueue;
    QueueHandle_t blockQueue;
    
    // Timing
    uint32_t lastBlockTime;
    uint32_t lastSyncTime;
    
public:
    BlockchainNode() {
        chain = (Block*)ps_malloc(sizeof(Block) * MAX_BLOCKS);
        mempool = (Transaction*)ps_malloc(sizeof(Transaction) * MAX_TRANSACTIONS);
        utxoSet = (UTXOEntry*)ps_malloc(sizeof(UTXOEntry) * MAX_TRANSACTIONS * 2);
        
        chainLength = 0;
        mempoolSize = 0;
        utxoCount = 0;
        balance = 1000000; // Initial balance
        peerCount = 0;
        
        chainMutex = xSemaphoreCreateMutex();
        mempoolMutex = xSemaphoreCreateMutex();
        txQueue = xQueueCreate(50, sizeof(Transaction));
        blockQueue = xQueueCreate(10, sizeof(Block));
    }
    
    void initialize() {
        Serial.println("[BLOCKCHAIN] Initializing node...");
        
        // Initialize EEPROM
        EEPROM.begin(512);
        
        // Load or generate keys
        if (!loadKeys()) {
            generateKeys();
            saveKeys();
        }
        
        // Generate address from public key
        generateAddress();
        
        // Create genesis block if needed
        if (chainLength == 0) {
            createGenesisBlock();
        }
        
        Serial.printf("[BLOCKCHAIN] Node initialized\n");
        Serial.printf("[BLOCKCHAIN] Address: %s\n", address);
        Serial.printf("[BLOCKCHAIN] Balance: %lu satoshis\n", balance);
    }
    
    void generateKeys() {
        // Generate random private key
        esp_fill_random(privateKey, 32);
        
        // Derive public key (simplified - use proper ECDSA in production)
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, privateKey, 32);
        mbedtls_sha256_finish(&ctx, publicKey);
        mbedtls_sha256_free(&ctx);
        
        publicKey[32] = 0x01; // Compressed key marker
    }
    
    void generateAddress() {
        // Generate Bitcoin-style address (simplified)
        uint8_t hash[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, publicKey, 33);
        mbedtls_sha256_finish(&ctx, hash);
        mbedtls_sha256_free(&ctx);
        
        // Convert to base58 (simplified - just hex for demo)
        sprintf(address, "ESP32");
        for (int i = 0; i < 15; i++) {
            char hex[3];
            sprintf(hex, "%02X", hash[i]);
            strcat(address, hex);
        }
    }
    
    bool loadKeys() {
        uint8_t magic = EEPROM.read(0);
        if (magic != 0xAA) return false;
        
        for (int i = 0; i < 32; i++) {
            privateKey[i] = EEPROM.read(1 + i);
        }
        for (int i = 0; i < 33; i++) {
            publicKey[i] = EEPROM.read(33 + i);
        }
        
        return true;
    }
    
    void saveKeys() {
        EEPROM.write(0, 0xAA); // Magic byte
        for (int i = 0; i < 32; i++) {
            EEPROM.write(1 + i, privateKey[i]);
        }
        for (int i = 0; i < 33; i++) {
            EEPROM.write(33 + i, publicKey[i]);
        }
        EEPROM.commit();
    }
    
    void createGenesisBlock() {
        Block genesis;
        genesis.index = 0;
        genesis.timestamp = millis() / 1000;
        strcpy(genesis.prevHash, "0000000000000000000000000000000000000000000000000000000000000000");
        strcpy(genesis.merkleRoot, "0000000000000000000000000000000000000000000000000000000000000000");
        genesis.nonce = 0;
        genesis.txCount = 0;
        
        calculateBlockHash(&genesis);
        
        xSemaphoreTake(chainMutex, portMAX_DELAY);
        memcpy(&chain[0], &genesis, sizeof(Block));
        chainLength = 1;
        xSemaphoreGive(chainMutex);
        
        Serial.println("[BLOCKCHAIN] Genesis block created");
    }
    
    void calculateBlockHash(Block* block) {
        char data[512];
        sprintf(data, "%lu%lu%s%s%lu%u", 
                block->index, 
                block->timestamp, 
                block->prevHash, 
                block->merkleRoot, 
                block->nonce,
                block->txCount);
        
        uint8_t hash[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, (uint8_t*)data, strlen(data));
        mbedtls_sha256_finish(&ctx, hash);
        mbedtls_sha256_free(&ctx);
        
        // Convert to hex string
        for (int i = 0; i < 32; i++) {
            sprintf(&block->hash[i * 2], "%02x", hash[i]);
        }
        block->hash[64] = '\0';
    }
    
    Transaction* createTransaction(const char* recipient, uint32_t amount) {
        if (amount > balance) {
            Serial.println("[ERROR] Insufficient balance");
            return nullptr;
        }
        
        static Transaction tx;
        strcpy(tx.from, address);
        strcpy(tx.to, recipient);
        tx.amount = amount;
        tx.timestamp = millis() / 1000;
        tx.nonce = random(0xFFFFFFFF);
        
        // Sign transaction
        signTransaction(&tx);
        
        // Calculate transaction ID
        calculateTxId(&tx);
        
        // Add to mempool
        xSemaphoreTake(mempoolMutex, portMAX_DELAY);
        if (mempoolSize < MAX_TRANSACTIONS) {
            memcpy(&mempool[mempoolSize++], &tx, sizeof(Transaction));
            balance -= amount; // Update balance optimistically
        }
        xSemaphoreGive(mempoolMutex);
        
        Serial.printf("[TX] Created: %s -> %s: %lu sat\n", tx.from, tx.to, tx.amount);
        
        return &tx;
    }
    
    void signTransaction(Transaction* tx) {
        // Simplified signature (use proper ECDSA in production)
        char data[256];
        sprintf(data, "%s%s%lu%lu%lu", tx->from, tx->to, tx->amount, tx->timestamp, tx->nonce);
        
        uint8_t hash[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, (uint8_t*)data, strlen(data));
        mbedtls_sha256_update(&ctx, privateKey, 32);
        mbedtls_sha256_finish(&ctx, hash);
        mbedtls_sha256_free(&ctx);
        
        for (int i = 0; i < 32; i++) {
            sprintf(&tx->signature[i * 2], "%02x", hash[i]);
        }
        tx->signature[64] = '\0';
    }
    
    void calculateTxId(Transaction* tx) {
        char data[512];
        sprintf(data, "%s%s%lu%lu%lu%s", 
                tx->from, tx->to, tx->amount, 
                tx->timestamp, tx->nonce, tx->signature);
        
        uint8_t hash[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, (uint8_t*)data, strlen(data));
        mbedtls_sha256_finish(&ctx, hash);
        mbedtls_sha256_free(&ctx);
        
        for (int i = 0; i < 32; i++) {
            sprintf(&tx->txid[i * 2], "%02x", hash[i]);
        }
        tx->txid[64] = '\0';
    }
    
    bool mineBlock() {
        if (mempoolSize < BLOCK_SIZE / 2) {
            return false; // Wait for more transactions
        }
        
        Serial.println("[MINING] Starting block mining...");
        digitalWrite(LED_STATUS, HIGH);
        
        Block newBlock;
        newBlock.index = chainLength;
        newBlock.timestamp = millis() / 1000;
        
        // Get previous block hash
        xSemaphoreTake(chainMutex, portMAX_DELAY);
        strcpy(newBlock.prevHash, chain[chainLength - 1].hash);
        xSemaphoreGive(chainMutex);
        
        // Add transactions from mempool
        xSemaphoreTake(mempoolMutex, portMAX_DELAY);
        newBlock.txCount = min(mempoolSize, BLOCK_SIZE);
        for (int i = 0; i < newBlock.txCount; i++) {
            memcpy(&newBlock.transactions[i], &mempool[i], sizeof(Transaction));
        }
        
        // Calculate merkle root
        calculateMerkleRoot(&newBlock);
        
        // Remove transactions from mempool
        mempoolSize -= newBlock.txCount;
        if (mempoolSize > 0) {
            memmove(mempool, &mempool[newBlock.txCount], sizeof(Transaction) * mempoolSize);
        }
        xSemaphoreGive(mempoolMutex);
        
        // Proof of work
        newBlock.nonce = 0;
        char target[DIFFICULTY + 1];
        memset(target, '0', DIFFICULTY);
        target[DIFFICULTY] = '\0';
        
        while (true) {
            calculateBlockHash(&newBlock);
            
            if (strncmp(newBlock.hash, target, DIFFICULTY) == 0) {
                break; // Found valid hash
            }
            
            newBlock.nonce++;
            
            // Allow other tasks to run
            if (newBlock.nonce % 1000 == 0) {
                vTaskDelay(1);
            }
        }
        
        // Add block to chain
        xSemaphoreTake(chainMutex, portMAX_DELAY);
        memcpy(&chain[chainLength++], &newBlock, sizeof(Block));
        xSemaphoreGive(chainMutex);
        
        digitalWrite(LED_STATUS, LOW);
        
        Serial.printf("[MINING] Block mined! Index: %lu, Hash: %.10s..., Nonce: %lu\n", 
                      newBlock.index, newBlock.hash, newBlock.nonce);
        
        return true;
    }
    
    void calculateMerkleRoot(Block* block) {
        if (block->txCount == 0) {
            strcpy(block->merkleRoot, "0000000000000000000000000000000000000000000000000000000000000000");
            return;
        }
        
        // Simplified merkle root (just hash all txids together)
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        
        for (int i = 0; i < block->txCount; i++) {
            mbedtls_sha256_update(&ctx, (uint8_t*)block->transactions[i].txid, 64);
        }
        
        uint8_t hash[32];
        mbedtls_sha256_finish(&ctx, hash);
        mbedtls_sha256_free(&ctx);
        
        for (int i = 0; i < 32; i++) {
            sprintf(&block->merkleRoot[i * 2], "%02x", hash[i]);
        }
        block->merkleRoot[64] = '\0';
    }
    
    bool validateBlock(Block* block) {
        // Check proof of work
        char target[DIFFICULTY + 1];
        memset(target, '0', DIFFICULTY);
        target[DIFFICULTY] = '\0';
        
        if (strncmp(block->hash, target, DIFFICULTY) != 0) {
            return false;
        }
        
        // Verify hash
        Block temp;
        memcpy(&temp, block, sizeof(Block));
        calculateBlockHash(&temp);
        
        if (strcmp(temp.hash, block->hash) != 0) {
            return false;
        }
        
        // Check previous hash
        if (chainLength > 0) {
            if (strcmp(block->prevHash, chain[chainLength - 1].hash) != 0) {
                return false;
            }
        }
        
        return true;
    }
    
    void broadcastTransaction(Transaction* tx) {
        if (peerCount == 0) return;
        
        digitalWrite(LED_TX, HIGH);
        
        StaticJsonDocument<512> doc;
        doc["type"] = "TX";
        doc["from"] = tx->from;
        doc["to"] = tx->to;
        doc["amount"] = tx->amount;
        doc["timestamp"] = tx->timestamp;
        doc["nonce"] = tx->nonce;
        doc["signature"] = tx->signature;
        doc["txid"] = tx->txid;
        
        char buffer[512];
        serializeJson(doc, buffer);
        
        for (int i = 0; i < peerCount; i++) {
            udp.beginPacket(peers[i], UDP_PORT);
            udp.write((uint8_t*)buffer, strlen(buffer));
            udp.endPacket();
        }
        
        digitalWrite(LED_TX, LOW);
    }
    
    void broadcastBlock(Block* block) {
        if (peerCount == 0) return;
        
        digitalWrite(LED_TX, HIGH);
        
        // Send block header first
        StaticJsonDocument<1024> doc;
        doc["type"] = "BLOCK";
        doc["index"] = block->index;
        doc["timestamp"] = block->timestamp;
        doc["prevHash"] = block->prevHash;
        doc["merkleRoot"] = block->merkleRoot;
        doc["nonce"] = block->nonce;
        doc["txCount"] = block->txCount;
        doc["hash"] = block->hash;
        
        char buffer[1024];
        serializeJson(doc, buffer);
        
        for (int i = 0; i < peerCount; i++) {
            udp.beginPacket(peers[i], UDP_PORT);
            udp.write((uint8_t*)buffer, strlen(buffer));
            udp.endPacket();
        }
        
        digitalWrite(LED_TX, LOW);
    }
    
    void handleNetworkMessage() {
        int packetSize = udp.parsePacket();
        if (packetSize == 0) return;
        
        digitalWrite(LED_RX, HIGH);
        
        char buffer[1024];
        int len = udp.read(buffer, sizeof(buffer) - 1);
        buffer[len] = '\0';
        
        StaticJsonDocument<1024> doc;
        DeserializationError error = deserializeJson(doc, buffer);
        
        if (!error) {
            const char* type = doc["type"];
            
            if (strcmp(type, "TX") == 0) {
                Transaction tx;
                strcpy(tx.from, doc["from"]);
                strcpy(tx.to, doc["to"]);
                tx.amount = doc["amount"];
                tx.timestamp = doc["timestamp"];
                tx.nonce = doc["nonce"];
                strcpy(tx.signature, doc["signature"]);
                strcpy(tx.txid, doc["txid"]);
                
                // Add to queue for processing
                xQueueSend(txQueue, &tx, 0);
                
            } else if (strcmp(type, "BLOCK") == 0) {
                Block block;
                block.index = doc["index"];
                block.timestamp = doc["timestamp"];
                strcpy(block.prevHash, doc["prevHash"]);
                strcpy(block.merkleRoot, doc["merkleRoot"]);
                block.nonce = doc["nonce"];
                block.txCount = doc["txCount"];
                strcpy(block.hash, doc["hash"]);
                
                // Add to queue for processing
                xQueueSend(blockQueue, &block, 0);
                
            } else if (strcmp(type, "PING") == 0) {
                // Respond with pong
                StaticJsonDocument<128> pong;
                pong["type"] = "PONG";
                pong["address"] = address;
                pong["height"] = chainLength;
                
                char response[128];
                serializeJson(pong, response);
                
                udp.beginPacket(udp.remoteIP(), UDP_PORT);
                udp.write((uint8_t*)response, strlen(response));
                udp.endPacket();
            }
        }
        
        digitalWrite(LED_RX, LOW);
    }
    
    void printStatus() {
        Serial.println("\n========== BLOCKCHAIN STATUS ==========");
        Serial.printf("Node Address: %s\n", address);
        Serial.printf("Balance: %lu satoshis\n", balance);
        Serial.printf("Chain Height: %u blocks\n", chainLength);
        Serial.printf("Mempool Size: %u transactions\n", mempoolSize);
        Serial.printf("UTXO Count: %u\n", utxoCount);
        Serial.printf("Connected Peers: %u\n", peerCount);
        Serial.printf("Free Heap: %u bytes\n", ESP.getFreeHeap());
        Serial.printf("Uptime: %lu seconds\n", millis() / 1000);
        
        if (chainLength > 0) {
            Serial.printf("Latest Block: #%lu (%.10s...)\n", 
                         chain[chainLength-1].index, 
                         chain[chainLength-1].hash);
        }
        Serial.println("=======================================\n");
    }
    
    uint32_t getChainLength() { return chainLength; }
    uint32_t getMempoolSize() { return mempoolSize; }
    uint32_t getBalance() { return balance; }
    const char* getAddress() { return address; }
};

// ==================== Global Variables ====================

BlockchainNode* node = nullptr;
TaskHandle_t miningTask = nullptr;
TaskHandle_t networkTask = nullptr;
TaskHandle_t telemetryTask = nullptr;

// ==================== FreeRTOS Tasks ====================

void miningTaskFunction(void* parameter) {
    Serial.println("[TASK] Mining task started");
    
    while (true) {
        // Mine block if conditions are met
        if (node->getMempoolSize() >= BLOCK_SIZE / 2) {
            node->mineBlock();
        }
        
        // Check for incoming blocks
        Block block;
        if (xQueueReceive(node->blockQueue, &block, 0) == pdTRUE) {
            if (node->validateBlock(&block)) {
                // Add to chain if valid
                Serial.printf("[BLOCKCHAIN] Received valid block #%lu\n", block.index);
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(5000)); // Check every 5 seconds
    }
}

void networkTaskFunction(void* parameter) {
    Serial.println("[TASK] Network task started");
    
    while (true) {
        // Handle network messages
        node->handleNetworkMessage();
        
        // Process transaction queue
        Transaction tx;
        if (xQueueReceive(node->txQueue, &tx, 0) == pdTRUE) {
            // Validate and add to mempool
            Serial.printf("[NETWORK] Received transaction: %s\n", tx.txid);
        }
        
        vTaskDelay(pdMS_TO_TICKS(10)); // Check every 10ms
    }
}

void telemetryTaskFunction(void* parameter) {
    Serial.println("[TASK] Telemetry task started");
    
    while (true) {
        node->printStatus();
        
        // Read sensors if available
        if (Wire.begin(IMU_SDA, IMU_SCL)) {
            // Read IMU data
            Wire.beginTransmission(0x68); // MPU6050 address
            Wire.write(0x3B); // Starting register
            Wire.endTransmission(false);
            Wire.requestFrom(0x68, 14, true);
            
            if (Wire.available() == 14) {
                int16_t ax = Wire.read() << 8 | Wire.read();
                int16_t ay = Wire.read() << 8 | Wire.read();
                int16_t az = Wire.read() << 8 | Wire.read();
                int16_t temp = Wire.read() << 8 | Wire.read();
                int16_t gx = Wire.read() << 8 | Wire.read();
                int16_t gy = Wire.read() << 8 | Wire.read();
                int16_t gz = Wire.read() << 8 | Wire.read();
                
                float temperature = (temp / 340.0) + 36.53;
                
                Serial.printf("[SENSORS] Temp: %.1f°C, Accel: (%d,%d,%d)\n", 
                             temperature, ax, ay, az);
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(30000)); // Every 30 seconds
    }
}

// ==================== Arduino Functions ====================

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n\n==================================================");
    Serial.println("     SPACE DOA - CubeSat Blockchain Controller");
    Serial.println("              ESP32 Implementation v1.0.0");
    Serial.println("==================================================\n");
    
    // Initialize pins
    pinMode(LED_STATUS, OUTPUT);
    pinMode(LED_TX, OUTPUT);
    pinMode(LED_RX, OUTPUT);
    
    // LED test sequence
    digitalWrite(LED_STATUS, HIGH);
    delay(200);
    digitalWrite(LED_TX, HIGH);
    delay(200);
    digitalWrite(LED_RX, HIGH);
    delay(200);
    digitalWrite(LED_STATUS, LOW);
    digitalWrite(LED_TX, LOW);
    digitalWrite(LED_RX, LOW);
    
    // Initialize WiFi
    Serial.printf("[WIFI] Connecting to %s", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println(" Connected!");
        Serial.printf("[WIFI] IP Address: %s\n", WiFi.localIP().toString().c_str());
    } else {
        Serial.println(" Failed!");
        Serial.println("[WIFI] Running in offline mode");
    }
    
    // Initialize UDP
    if (WiFi.status() == WL_CONNECTED) {
        node->udp.begin(UDP_PORT);
        Serial.printf("[NETWORK] UDP listening on port %d\n", UDP_PORT);
    }
    
    // Initialize SD card (optional)
    if (SD.begin(SD_CS)) {
        Serial.printf("[SD] Card initialized. Size: %lluMB\n", SD.cardSize() / (1024 * 1024));
    } else {
        Serial.println("[SD] Card initialization failed (optional)");
    }
    
    // Initialize blockchain node
    node = new BlockchainNode();
    node->initialize();
    
    // Create FreeRTOS tasks
    xTaskCreatePinnedToCore(
        miningTaskFunction,
        "Mining",
        STACK_SIZE,
        NULL,
        2,
        &miningTask,
        1  // Core 1
    );
    
    xTaskCreatePinnedToCore(
        networkTaskFunction,
        "Network",
        STACK_SIZE,
        NULL,
        3,
        &networkTask,
        1  // Core 1
    );
    
    xTaskCreatePinnedToCore(
        telemetryTaskFunction,
        "Telemetry",
        STACK_SIZE / 2,
        NULL,
        1,
        &telemetryTask,
        0  // Core 0
    );
    
    Serial.println("\n[SYSTEM] All tasks started. Node operational.\n");
    
    // Create initial transactions for testing
    delay(2000);
    node->createTransaction("ESP32ABCDEF1234567890ABCDEF12345", 1000);
    node->createTransaction("ESP32FEDCBA0987654321FEDCBA09876", 2000);
}

void loop() {
    // Handle serial commands
    if (Serial.available()) {
        String command = Serial.readStringUntil('\n');
        command.trim();
        
        if (command == "status") {
            node->printStatus();
            
        } else if (command.startsWith("send ")) {
            // Parse: send <address> <amount>
            int spaceIdx = command.indexOf(' ', 5);
            if (spaceIdx > 0) {
                String addr = command.substring(5, spaceIdx);
                uint32_t amount = command.substring(spaceIdx + 1).toInt();
                
                Transaction* tx = node->createTransaction(addr.c_str(), amount);
                if (tx) {
                    node->broadcastTransaction(tx);
                    Serial.printf("[CMD] Transaction sent: %s\n", tx->txid);
                }
            }
            
        } else if (command == "mine") {
            Serial.println("[CMD] Force mining block...");
            if (node->mineBlock()) {
                Serial.println("[CMD] Block mined successfully");
            } else {
                Serial.println("[CMD] Mining failed - not enough transactions");
            }
            
        } else if (command == "peers") {
            Serial.printf("[CMD] Connected peers: %d\n", node->peerCount);
            
        } else if (command == "restart") {
            Serial.println("[CMD] Restarting...");
            ESP.restart();
            
        } else if (command == "help") {
            Serial.println("\n=== Available Commands ===");
            Serial.println("status          - Show blockchain status");
            Serial.println("send <addr> <amount> - Send transaction");
            Serial.println("mine           - Force mine a block");
            Serial.println("peers          - Show connected peers");
            Serial.println("restart        - Restart the node");
            Serial.println("help           - Show this help");
            Serial.println("========================\n");
            
        } else {
            Serial.println("[CMD] Unknown command. Type 'help' for available commands.");
        }
    }
    
    // Watchdog reset
    esp_task_wdt_reset();
    
    // Main loop runs at lower frequency
    delay(100);
}