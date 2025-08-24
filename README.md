# SPACE DOA - CubeSat Blockchain Controller
https://github.com/agreatopportunity/space_doa_esp32/tree/main

## 🛰️ About The Project

This repository contains the firmware for the **SPACE DOA (Decentralized Orbital Asset)** project. It's a lightweight blockchain node specifically designed to run on an **ESP32 microcontroller**, making it suitable for deployment on a CubeSat in Low Earth Orbit (LEO).

The goal is to create a resilient, decentralized network that operates in space, providing a foundation for future orbital applications like secure satellite-to-satellite communication, asset tracking, and autonomous smart contracts in a space environment.

This implementation handles everything from cryptographic operations and peer-to-peer networking to real-time task management for the harsh conditions of space.

---

## ✨ Key Features

* **Lightweight Blockchain Node:** Full capabilities for creating, signing, and validating transactions and blocks.
* **Peer-to-Peer Networking:** Utilizes WiFi for ground testing and development, with support for **LoRa** for long-range, low-power communication between satellites.
* **Real-Time Operating System (RTOS):** Built on **FreeRTOS** to manage multiple tasks concurrently, ensuring reliable operation for critical processes like network communication, blockchain processing, and system monitoring.
* **Hardware Integration:** Includes drivers and pin definitions for essential CubeSat hardware:
    * Status LEDs
    * LoRa Radio Module (SX1276/SX1278)
    * Inertial Measurement Unit (IMU) for orientation tracking
    * SD Card for expanded storage of the blockchain ledger.
* **Robust Cryptography:** Uses the **mbedTLS** library for industry-standard **SHA-256** hashing and **ECDSA** for secure digital signatures.
* **Persistent Storage:** Leverages onboard **EEPROM** for storing critical node information like private keys and configuration settings.
* **Interactive Serial Interface:** A command-line interface accessible via serial monitor for debugging, testing, and direct interaction with the node.
* **System Resilience:** An integrated **watchdog timer** ensures the system automatically reboots if it becomes unresponsive, a critical feature for autonomous orbital operation.

---

## 🛠️ Hardware Requirements

This firmware is designed for the following hardware components. While some are optional for basic testing, a full deployment would require them all.

* **Microcontroller:** ESP32 DevKit (ESP32-WROOM-32)
* **Long-Range Radio:** LoRa Module (SX1276 / SX1278)
* **Orientation Sensor:** MPU6050 IMU (Inertial Measurement Unit)
* **Storage:** SD Card Module
* **Basic Components:** Status LEDs (3), appropriate wiring, and power supply.

---

## 🚀 Getting Started

To get this firmware running on your own ESP32, follow these steps.

### Prerequisites

* [Visual Studio Code](https://code.visualstudio.com/)
* [PlatformIO IDE Extension](https://platformio.org/install/ide?install=vscode) for VS Code. (Recommended)
* The required hardware listed above.

### Installation & Flashing

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/agreatopportunity/space_doa_esp32](https://github.com/agreatopportunity/space_doa_esp32)
    ```
2.  **Open the project in VS Code:**
    * Open Visual Studio Code.
    * Click on the PlatformIO icon on the left sidebar.
    * Click "Open Project" and select the cloned repository folder.
3.  **Configure Network (Optional):**
    * Open `src/space_doa_micro.c`.
    * Modify the `WIFI_SSID` and `WIFI_PASS` constants to connect to your local WiFi network for testing.
4.  **Build and Upload:**
    * Connect your ESP32 DevKit to your computer via USB.
    * In PlatformIO, click the "Upload" button (an arrow icon) in the bottom status bar. PlatformIO will automatically compile the code, install dependencies, and flash the firmware to your ESP32.

---

## 💻 Usage & Serial Commands

Once the firmware is running, you can interact with the blockchain node using a serial monitor (like the one built into PlatformIO) at a baud rate of **115200**.

The following commands are available:

| Command                  | Description                                                                                             | Example         |
| ------------------------ | ------------------------------------------------------------------------------------------------------- | --------------- |
| `status`                 | Shows the current status of the blockchain node, including block height, balance, and peer count.       | `status`        |
| `send <addr> <amount>`   | Creates and broadcasts a new transaction to the specified address with the given amount.                | `send 1A... 500`|
| `mine`                   | Manually attempts to mine a new block with the transactions currently in the mempool.                     | `mine`          |
| `peers`                  | Displays the number of currently connected peers in the network.                                        | `peers`         |
| `restart`                | Reboots the ESP32 microcontroller.                                                                      | `restart`       |
| `help`                   | Displays the list of available commands.                                                                | `help`          |
