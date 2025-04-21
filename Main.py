import os
import sys
# from scapy.all import sniff, ARP, Raw, IP, TCP
from scapy.all import *

# Create logs folder if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Store known IP-MAC mappings
ip_mac_map = {}

# Log suspicious behavior to a file
def log_alert(alert_type, details):
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {alert_type}: {details}\n"
    print(log_entry.strip())
    with open("logs/alerts.log", "a") as f:
        f.write(log_entry)

# Detect unencrypted HTTP credentials
def detect_http_credentials(packet):
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            if "username=" in payload or "password=" in payload:
                log_alert("Unencrypted Credential Detected", payload)
        except Exception:
            pass

# Detect ARP spoofing
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        if ip in ip_mac_map and ip_mac_map[ip] != mac:
            alert_msg = f"{ip} changed MAC from {ip_mac_map[ip]} to {mac}"
            log_alert("ARP Spoofing Detected", alert_msg)
        ip_mac_map[ip] = mac

# Packet handler
def packet_handler(packet):
    if packet.haslayer(ARP):
        detect_arp_spoof(packet)
    elif packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        detect_http_credentials(packet)

# --- Test Mode ---

def run_test_mode():
    print("Running in TEST MODE...\n")

    # Simulate ARP spoofing
    from scapy.all import ARP

    fake_arp1 = ARP(op=2, psrc="192.168.0.1", hwsrc="aa:bb:cc:dd:ee:ff")
    fake_arp2 = ARP(op=2, psrc="192.168.0.1", hwsrc="11:22:33:44:55:66")

    packet_handler(fake_arp1)
    packet_handler(fake_arp2)

    # Simulate unencrypted HTTP credentials
    fake_http = ip(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80) / Raw(load="POST /login HTTP/1.1\r\n\r\nusername=test&password=1234")
    packet_handler(fake_http)

    # Scanning a port
    try:
        # E.g. 8.8.8.8
        host = input("Enter a host address: ")
        # E.g. 53,8080
        p = list(input("Enter the ports to scan: ").split(","))
        temp = map(int,p)
        ports = list(temp)

        if(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",host)):
            print("\n\nScanning...")
            print("Host: ", host)
            print("Ports: ",ports)

            ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),verbose=0, timeout=2)

            for (s,r) in ans:
                print("[+] {} Open".format(s[TCP].dport))

    except (ValueError, RuntimeError, TypeError, NameError):
        print("[-] Some Error Occured")
        print("[-] Exiting..")


# --- Main ---

if __name__ == "__main__":
    if "--test" in sys.argv:
        run_test_mode()
    else:
        print("Starting packet capture (press Ctrl+C to stop)...")
        try:
            sniff(prn=packet_handler, store=0)
        except KeyboardInterrupt:
            print("\nCapture stopped.")
