from scapy.all import IP, TCP, Raw, send

# Modify these values if needed
target_ip = "127.0.0.1"  # Loopback
target_port = 80

payload = "POST /login HTTP/1.1\r\nHost: test.local\r\n\r\nusername=admin&password=1234"
packet = IP(dst=target_ip)/TCP(dport=target_port, sport=12345)/Raw(load=payload)

print("[*] Sending fake HTTP POST with credentials...")
send(packet, verbose=False)
print("[+] Packet sent.")
