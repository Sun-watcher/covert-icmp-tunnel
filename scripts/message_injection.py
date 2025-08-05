#!/usr/bin/env python3
from scapy.all import *
import subprocess

# ---------------- Détection automatique du host ----------------

def detect_host():
    result = subprocess.run(['ip', 'addr'], stdout=subprocess.PIPE, text=True)
    output = result.stdout

    if "10.87.87.1" in output:
        return "h1"
    elif "10.87.87.2" in output:
        return "h2"
    else:
        return "unknown"

host = detect_host()
if host == "unknown":
    print("[-] Hôte inconnu, arrêt du script.")
    exit(1)

ip_src = "10.87.87.1" if host == "h1" else "10.87.87.2"
ip_dst = "10.87.87.2" if host == "h1" else "10.87.87.1"

INTERFACE_INJECTION = f"{host}-injection"
INTERFACE = f"{host}-canal"
ADRESSE_MAC = get_if_hwaddr(INTERFACE)
PORT = 6789

# ---------------- Interaction utilisateur ----------------

print("=== Injection interactive ===")
proto = ""
while proto not in ["udp", "tcp"]:
    proto = input("Protocole à utiliser (udp / tcp) : ").strip().lower()

message = ""
if proto in ["udp", "tcp"]:
    message = input("Message à envoyer : ").strip()
    if not message:
        print("[-] Message vide, arrêt.")
        exit(1)

# ---------------- Envoi du paquet ----------------

if proto == "udp":
    print(f"[→] Envoi UDP de '{message}' vers {ip_dst}:{PORT}")
    sendp(
        Ether(src=RandMAC(), dst=ADRESSE_MAC) /
        IP(src=ip_src, dst=ip_dst) /
        UDP(sport=PORT, dport=PORT) /
        Raw(load=message.encode()),
        iface=INTERFACE_INJECTION
    )
else:
    print(f"[→] Envoi TCP SYN vers {ip_dst}:{PORT}")
    sendp(
        Ether(src=RandMAC(), dst=ADRESSE_MAC) /
        IP(src=ip_src, dst=ip_dst) /
        TCP(sport=PORT, dport=PORT, flags='S') /
        Raw(load=message.encode()),
        iface=INTERFACE_INJECTION
    )
