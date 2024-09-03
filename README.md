# Network Sniffer Tool

## Overview

The Packet Sniffer Tool is a Python script designed to capture and log network packets. It uses the Scapy library to sniff packets from a specified network interface, filter them based on defined rules, and log details such as packet protocol, source and destination IP addresses, and ports. The tool supports both file and console logging and includes features for graceful shutdown and dynamic interface detection.

## Features

- Captures packets from a specified network interface.
- Logs packet details to a timestamped log file and to the console.
- Supports TCP, UDP, and ICMP packets, with options for handling non-IP packets.
- Allows dynamic detection and validation of network interfaces.
- Handles errors gracefully and supports graceful shutdown.

## Prerequisites

- Python 3.x
- Scapy library

## Installation

1. **Install Python 3**: Ensure Python 3 is installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

2. **Install Scapy**: Install the Scapy library using pip:
   ```bash
   pip install scapy


Configuration

    Set the Network Interface: Edit the interface variable in the script to match your network interface name (e.g., wlan0 for wireless or eth0 for wired interfaces).

    Define Packet Filters: Modify the filter_rule variable to set specific packet capture filters (e.g., "tcp port 80"). Leave it empty ("") to capture all packets.
