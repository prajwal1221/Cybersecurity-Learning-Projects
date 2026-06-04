from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


def process_packet(packet):

    print("\n=== New Packet Captured ===")

    # Check if packet has IP layer
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")
        print(f"Packet Size    : {len(packet)} bytes")

        # Detect protocol type
        if packet.haslayer(TCP):
            print("Protocol Name  : TCP")

        elif packet.haslayer(UDP):
            print("Protocol Name  : UDP")

        elif packet.haslayer(ICMP):
            print("Protocol Name  : ICMP")

        else:
            print("Protocol Name  : Other")


print("Starting Packet Sniffer...")
print("Press CTRL + C to stop.\n")

sniff(prn=process_packet, store=False)