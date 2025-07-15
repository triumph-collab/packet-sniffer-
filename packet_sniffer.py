from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        if proto == 6:
            transport = "TCP"
        elif proto == 17:
            transport = "UDP"
        else:
            transport = "Other"

        info = (
            f"[+] Packet Captured:\n"
            f"    Source IP      : {src_ip}\n"
            f"    Destination IP : {dst_ip}\n"
            f"    Protocol       : {proto}\n"
            f"    Transport Layer: {transport}\n\n"
        )

        # Print to screen
        print(info)

        # Append to file
        with open("captured_packets.txt", "a", encoding="utf-8") as f:
            f.write(info)

# Start sniffing
print("[*] Starting Packet Sniffer... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=False)
