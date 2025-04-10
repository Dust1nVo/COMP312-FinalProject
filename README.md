# COMP312-FinalProject

The purpose of this tool is to demonstrate how attackers might exploit insecure network behaviors and raise awareness about best practices in network security.

## Features
- **Live Packet Capture** using Scapy
- **Unencrypted Credential Detection** in HTTP traffic
- **ARP Spoofing Detection** by monitoring MAC-to-IP inconsistencies
- **Spoofed Packet Injection** for testing ARP-based man-in-the-middle scenarios
- Planned: DNS spoofing detection, malformed packet analysis, basic pattern recognition

## Why This Matters
This project is intended for **cybersecurity education and research**. It helps users understand real-world vulnerabilities in network communication and how proactive detection can mitigate potential attacks.

## Project Files
- `main.py` – Core logic for live capture, detection, and logging
- `project_overview.txt` – Mission Statement and Code of Conduct
- `logs/` – Directory where alert logs are stored
- `README.md` – This file

## Authors
- Team 5: COMP 312 01E
- Matthew Caballero, Xander Estevez, Dustin Vo

## Setup & Usage
```bash
pip install scapy
sudo python main.py

