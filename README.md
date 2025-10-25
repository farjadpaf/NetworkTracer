# Packet Sniffer and Dissector Program

## Overview

This C++ program captures network packets from a specified network interface, dissects them to reveal protocol layers, filters packets based on source and destination IP addresses, and can replay selected packets back into the network. It uses raw sockets to monitor live traffic and maintains captured packets in a dynamic queue for processing.

## How to Run

### Prerequisites

* Linux-based system (raw sockets require root privileges)
* C++ compiler supporting C++11 or higher
* Root permissions to capture packets

### Steps

1. Compile the program:

   ```
   g++ PacketTracer.cpp -o PacketTracer
   ```
2. Run the program with root privileges:

   ```
   sudo ./PacketTracer
   ```
3. Enter the network interface when prompted:
(to check for your network interface run 

   ```
   Enter network interface to capture packets (e.g., eth0): 
   ```
4. Use the interactive menu to capture, dissect, filter, replay, or display packets.

## Program Functionalities

### 1. Packet Capture

* Captures live network packets on the specified interface.
* Default capture duration is 60 seconds (customizable).
* Each packet is stored in a dynamic queue (`Queue`) with metadata:

  * Packet number
  * Timestamp
  * Packet size
  * Source and destination IP
  * Source and destination ports

### 2. Packet Dissection

* Uses a stack (`LayersStack`) to track protocol layers of each packet.
* Dissects the following layers:

  * Ethernet
  * IPv4 / IPv6
  * TCP / UDP
  
* Displays the layer stack for each packet in hierarchical order.

### 3. Display Captured Packets

* Prints a summary of all captured packets:

  * Packet number
  * Timestamp
  * Packet size
  * Source and destination IP

### 4. Packet Filtering

* Filters captured packets based on:

  * Source IP
  * Destination IP
  * Maximum allowed packet size (1500 bytes)
* Stores valid packets in a **replay queue** and invalid packets in a **failed queue**.
* Shows the total number of filtered and failed packets.

### 5. Replay Packets

* Replays filtered packets back to the network using raw sockets.
* Retries up to 2 times if replay fails.
* Introduces a delay proportional to packet size to simulate real-time transmission.

### 6. Display Filtered / Failed Packets

* Filtered packets: Packets ready to be replayed.
* Failed packets: Packets exceeding size or failed replay attempts.

### 7. Exit

* Closes raw socket gracefully.
* Frees all allocated memory (packets, layers stack, queues).

## Data Structures Used

| Component          | Purpose                                                                  |
| ------------------ | ------------------------------------------------------------------------ |
| `Node`             | Stores individual packet data and metadata.                              |
| `Queue`            | Stores captured packets and allows traversal.                            |
| `LayersStack`      | Tracks protocol layers during dissection (stack structure).              |
| `PacketCapture`    | Manages raw socket capture, binding to interface, and receiving packets. |
| `packetDissection` | Parses Ethernet, IP, TCP/UDP layers and populates `LayersStack`.         |
| `Filter`           | Filters packets based on IP/size and manages replay/failed queues.       |

## Example Workflow

1. Start program and enter interface: `lo` when i ran on my laptop .
2. Capture packets for 60 seconds.
3. Dissect all captured packets:

   ```
   Starting dissection of Packet Number: 1
   -->Ethernet
   -->IPv4
   -->TCP
   -->TCPPorts
   Dissection complete.
   ```
4. Filter packets with specific source and destination IPs.
5. Replay filtered packets to the network.
6. View failed packets if any.
7. Exit the program.

## Notes

* Root privileges are required to use raw sockets.
* The program supports both IPv4 and IPv6.
* Packet dissection shows a hierarchical stack of layers for easier analysis.
* The stack is **packet-specific**; each dissection starts a fresh layer stack.

