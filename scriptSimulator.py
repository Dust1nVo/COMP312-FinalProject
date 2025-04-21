import random
import time
from datetime import datetime
import os

# Make sure logs folder exists
os.makedirs("logs", exist_ok=True)

# Sample IPs and MACs
ips = ["192.168.0.1", "192.168.0.10", "10.0.0.5", "172.16.1.1"]
macs = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "de:ad:be:ef:00:01", "00:11:22:33:44:55"]

# Sample credentials
usernames = ["admin", "user1", "alice", "bob", "test"]
passwords = ["1234", "password", "letmein", "hunter2", "qwerty"]

def write_alert(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {msg}\n"
    with open("logs/alerts.log", "a") as f:
        f.write(full_message)
    print(f"✔️ {msg}")

def generate_arp_alert():
    ip = random.choice(ips)
    old_mac = random.choice(macs)
    new_mac = random.choice([m for m in macs if m != old_mac])
    message = f"ARP Spoofing Detected: {ip} changed MAC from {old_mac} to {new_mac}"
    write_alert(message)

def generate_credential_alert():
    user = random.choice(usernames)
    pwd = random.choice(passwords)
    message = f"Unencrypted Credential Detected: POST /login username={user}&password={pwd}"
    write_alert(message)

def generate_random_alert():
    if random.random() < 0.5:
        generate_arp_alert()
    else:
        generate_credential_alert()

if __name__ == "__main__":
    print("Simulating random alerts every 5 seconds. Press Ctrl+C to stop.")
    try:
        while True:
            generate_random_alert()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nSimulation stopped.")
