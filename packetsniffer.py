from scapy.all import sniff, IP, TCP, UDP, ICMP, raw
import logging
import sys
from datetime import datetime
import signal
import os

# Setup logging to capture packet details in a text file and stdout
log_file = f"packet_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logging.getLogger().addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logging.getLogger().addHandler(console_handler)

# Function to handle each packet and log details
def packet_callback(packet):
    try:
        packet_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Layer 3 (Network layer)
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            # Layer 4 (Transport layer)
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            elif ICMP in packet:
                proto = "ICMP"
                sport = None
                dport = None
            else:
                proto = "OTHER"
                sport = None
                dport = None

            # Build log message
            log_message = f"Time: {packet_time}, Protocol: {proto}, Src IP: {ip_src}, Dst IP: {ip_dst}"
            if sport and dport:
                log_message += f", Src Port: {sport}, Dst Port: {dport}"

            # Print the log message to the console
            print(log_message)

            # Log packet details to file
            logging.info(log_message)

            # Optionally, log the raw packet data (hex format)
            logging.info(f"Raw Packet: {raw(packet).hex()}")

        else:
            # Handle non-IP packets
            print(f"Non-IP packet: {packet.summary()}")
            logging.info(f"Non-IP packet: {packet.summary()}")

    except Exception as e:
        # In case of any errors, log them
        logging.error(f"Error processing packet: {e}")

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    print("\nShutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Function to check if the interface exists
def check_interface(interface):
    try:
        if interface in os.popen('ls /sys/class/net').read():
            return True
        else:
            print(f"Error: Interface {interface} does not exist.")
            sys.exit(1)
    except Exception as e:
        print(f"Error checking interface: {e}")
        sys.exit(1)

# Define your interface and filter (customize these)
interface = "wlan0"  # Change to your interface
filter_rule = ""  # Use "" to capture all packets, or set a specific filter

# Check if the interface exists
check_interface(interface)

# Start sniffing packets with filtering and callback
print("Starting packet capture...")
try:
    sniff(iface=interface, filter=filter_rule, prn=packet_callback, store=False)
except Exception as e:
    print(f"Error starting packet capture: {e}")
    logging.error(f"Error starting packet capture: {e}")
