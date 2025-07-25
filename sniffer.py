# Import necessary modules from the scapy library
# IP: Represents the Internet Protocol layer (handles IP addresses)
# TCP: Represents the Transmission Control Protocol layer (for reliable connections)
# UDP: Represents the User Datagram Protocol layer (for faster, less reliable connections)
# sniff: The main function to capture packets
from scapy.all import IP, TCP, UDP, sniff

# --- Packet Processing Function ---
# This function will be called for every packet that is captured.
# It takes one argument: 'packet', which is the captured network packet object.
def packet_analyzer(packet):
    """
    Analyzes a captured network packet and prints relevant information.
    """
    print("\n--- New Packet Captured ---")

    # Check if the packet has an IP layer.
    # Most internet traffic uses IP, so this is a common starting point.
    if IP in packet:
        # Get the IP layer of the packet
        ip_layer = packet[IP]

        # Print Source and Destination IP addresses
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}") # Protocol number (e.g., 6 for TCP, 17 for UDP)

        # Check for TCP layer
        # TCP is used for applications like web browsing (HTTP/HTTPS), email (SMTP, POP3, IMAP), etc.
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"  Protocol Name: TCP")
            print(f"  Source Port: {tcp_layer.sport}")
            print(f"  Destination Port: {tcp_layer.dport}")

            # Try to get the raw payload data (the actual content being sent)
            # This might not always be present or readable, especially for encrypted traffic.
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                print(f"  TCP Payload (first 50 bytes): {payload[:50]}...") # Print first 50 bytes
            else:
                print("  No TCP Payload or encrypted.")

        # Check for UDP layer
        # UDP is often used for applications where speed is more critical than guaranteed delivery,
        # like video streaming, online gaming, DNS queries.
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"  Protocol Name: UDP")
            print(f"  Source Port: {udp_layer.sport}")
            print(f"  Destination Port: {udp_layer.dport}")

            # Try to get the raw payload data
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                print(f"  UDP Payload (first 50 bytes): {payload[:50]}...") # Print first 50 bytes
            else:
                print("  No UDP Payload or encrypted.")

        # If it's an IP packet but neither TCP nor UDP (e.g., ICMP for ping)
        else:
            print(f"  Other IP Protocol (Type: {ip_layer.proto})")
            # You can add more checks here for other protocols like ICMP (ping)

    else:
        # If the packet doesn't have an IP layer (e.g., ARP, Ethernet frames directly)
        print("  Non-IP Packet (e.g., ARP, Ethernet)")
        # You can print the summary of the packet to see its type
        # print(packet.summary())

# --- Main Sniffer Logic ---
def start_sniffer(count=0, iface=None):
    """
    Starts the network sniffer.

    Args:
        count (int): Number of packets to capture. 0 means infinite.
        iface (str): The network interface to sniff on (e.g., "eth0", "Wi-Fi").
                     If None, scapy tries to find a default interface.
    """
    print("\n--- Starting Network Sniffer ---")
    print("Press Ctrl+C to stop the sniffer.")

    # You can specify an interface if you know it, e.g., iface="Ethernet" or iface="Wi-Fi"
    # To find your interface names, you can run `scapy.all.get_if_list()` in a Python interpreter.
    # Or, you can leave it as None to let scapy try to pick one.
    interface_to_sniff = iface

    try:
        # sniff() is the core scapy function for packet capturing.
        # prn: Specifies the function to call for each captured packet.
        # count: The number of packets to capture. 0 means capture indefinitely.
        # iface: The network interface to listen on.
        # store: Set to False to prevent storing packets in memory (good for long captures).
        sniff(prn=packet_analyzer, count=count, iface=interface_to_sniff, store=False)
    except KeyboardInterrupt:
        # This block catches Ctrl+C, allowing for a graceful exit.
        print("\n--- Sniffer Stopped by User ---")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Please ensure you have the necessary permissions (e.g., run as administrator/root).")
        print("Also, check your network interface name if you specified one.")


# --- Entry Point ---
# This ensures that start_sniffer() is called only when the script is executed directly.
if __name__ == "__main__":
    # You can specify the number of packets to capture here.
    # For example, count=10 to capture 10 packets then stop.
    # Set count=0 for continuous capture until Ctrl+C.
    packet_limit = 0

    # OPTIONAL: Specify your network interface name here.
    # On Windows, it might be something like "Ethernet" or "Wi-Fi".
    # On Linux, it might be "eth0", "wlan0", etc.
    # If you don't know, leave it as None, and scapy will try to auto-detect.
    # To find interface names:
    # 1. Open Python interpreter: `python`
    # 2. `from scapy.all import get_if_list`
    # 3. `get_if_list()`
    network_interface = None # Or e.g., "Ethernet", "Wi-Fi", "eth0"

    start_sniffer(count=packet_limit, iface=network_interface)
