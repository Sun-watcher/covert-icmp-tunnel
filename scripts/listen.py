#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import defragment
conf.sniff_promisc = True

from hide_and_send import *
import subprocess

# ------------------- Détection automatique du host -------------------

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

if host == "h1":
    HOST_IP = "10.87.87.1"
    TARGET_IP = "10.87.87.2"
    HOST_PUBLIC_IP = "192.168.10.1"
    PRINCIPAL_INTERFACE = "h1-eth0"
    CANAL_INTERFACE = "h1-canal"
    INJECTION_INTERFACE = "h1-injection"
elif host == "h2":
    HOST_IP = "10.87.87.2"
    TARGET_IP = "10.87.87.1"
    HOST_PUBLIC_IP = "192.168.20.1"
    PRINCIPAL_INTERFACE = "h2-eth0"
    CANAL_INTERFACE = "h2-canal"
    INJECTION_INTERFACE = "h2-injection"
else:
    print("[-] Hôte inconnu, arrêt du script.")
    exit(1)

print(f"[+] Script lancé sur {host} avec interface principale {PRINCIPAL_INTERFACE} et canal {CANAL_INTERFACE}")

# ------------------- Fonctions de traitement -------------------

def process_outgoing_packet(packet):
    if IP in packet and packet[IP].dst.startswith("10.87.87.") and packet[IP].src == HOST_IP:
        payload = bytes(packet[Raw].load) if Raw in packet else b""
        if payload:
            print(f"[→] Paquet à cacher détecté : {payload}")

            hidden_payload = b"HIDE:" + payload

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            protocole = "TCP" if TCP in packet else "UDP"

            hide_message_in_icmp(hidden_payload, src_ip, dst_ip, sport, dport, protocole)
            print("[✔] Message caché et injecté.")
        else:
            print("[!] Aucun payload détecté dans le paquet à cacher.")

# ------------------- Traitement ICMP entrant -------------------

def process_incoming_icmp(packet):
    """Gère les paquets ICMP entrants, fragmentés ou non."""
    fragment_id = packet[IP].id

    if packet[IP].frag > 0 or packet[IP].flags & 1:
        print(f"[🔄] Fragment ICMP détecté (ID {fragment_id}), ajout au tampon.")
        fragments_buffer.setdefault(fragment_id, []).append(packet)
        try_reassemble_fragments(fragment_id)


# ------------------- Buffers et fragments -------------------

fragments_buffer = {}

def try_reassemble_fragments(fragment_id):
    """Réassemble manuellement les fragments ICMP en un message complet."""
    try:
        fragments = fragments_buffer.get(fragment_id, [])
        if not fragments:
            return

        # Tri des fragments par offset
        fragments.sort(key=lambda pkt: pkt[IP].frag)

        complete_data = b""
        last_fragment = False

        for frag in fragments:
            if Raw in frag:
                complete_data += bytes(frag[Raw].load)

            # Vérifie le dernier fragment (flag MF = 0)
            if frag[IP].flags == 0:
                last_fragment = True

        if last_fragment:
            # Tous les fragments ont été reçus
            print("[🧩] Tous les fragments reçus, message complet prêt.")
            dummy_ip = fragments[0][IP]
            dummy_ip.len = len(complete_data)
            dummy_ip.flags = 0
            dummy_ip.frag = 0
            dummy_ip.id = fragment_id

            reconstructed_packet = IP(src=dummy_ip.src, dst=dummy_ip.dst) / ICMP(type=8) / Raw(load=complete_data)

            extract_and_send_hidden_data(reconstructed_packet)
            fragments_buffer.pop(fragment_id)
        else:
            print("[⏳] Attente d'autres fragments ICMP (ID {}).".format(fragment_id))

    except Exception as e:
        print(f"[⚠] Erreur dans le réassemblage manuel : {e}")


# ------------------- Extraction et envoi -------------------

def extract_and_send_hidden_data(packet):
    """Vérifie la présence d'un message caché et l'envoie sur le canal."""
    # Vérifier si le paquet contient une charge utile RAW
    raw_bytes = bytes(packet[Raw].load) if Raw in packet else bytes(packet)
    #print("Détails du paquet : ", packet.show())

    # Vérifier si un message caché est présent
    if b"HIDE:" in raw_bytes:
        hidden_data = raw_bytes.split(b"HIDE:", 1)[1]
        # Ajouter un retour à la ligne pour la lisibilité
        print(f"[🔍] Message caché détecté : {hidden_data.decode(errors='ignore')}")

        # Extraire l'en-tête IP et créer un nouveau paquet avec l'en-tête IP d'origine
        ip_header = packet[IP]  # Récupérer l'en-tête IP du paquet
        new_packet_udp = IP(src=ip_header.src, dst=ip_header.dst) / UDP(sport=5678, dport=6789) / Raw(load=hidden_data)
        new_packet_tcp = IP(src=ip_header.src, dst=ip_header.dst) / TCP(sport=5678, dport=6789) / Raw(load=hidden_data)

        # Envoi du paquet
        send(new_packet_tcp, iface=CANAL_INTERFACE)
        send(new_packet_udp, iface=CANAL_INTERFACE)
        print("[✔] Message redirigé vers le canal.")
    else:
        print("[⚠] Aucun message caché trouvé.")

# ------------------- Sniffer principal -------------------

def packet_callback(packet):
    print(f"[+] Paquet détecté : {packet.summary()}")
    print(f"Paquet reçu sur interface : {packet.sniffed_on}")

    # Ne pas traiter les paquets ICMP qu'on a nous-mêmes injectés
    if packet.sniffed_on == INJECTION_INTERFACE:
        print("[↩] Paquet injecté détecté sur interface d'injection, ignoré.")
        return

    if not IP in packet:
        print("[!] Paquet non-IP détecté.")
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    ip_proto = packet[IP].proto
    is_fragment = packet[IP].frag > 0 or packet[IP].flags == 1

    print(f"[+] IP : {ip_src} -> {ip_dst}")

    # 1. Paquet sortant depuis HOST_IP vers réseau caché
    if ip_src == HOST_IP and ip_dst == TARGET_IP:
        print("[→] Paquet sortant détecté à destination du réseau caché.")
        process_outgoing_packet(packet)
        return

    # 2. Paquet entrant mais pas pour nous
    if ip_dst != HOST_PUBLIC_IP:
        print(f"[✘] Paquet non destiné à {HOST_PUBLIC_IP}, ignoré.")
        return

    # 3. Paquet ICMP complet
    if ICMP in packet and packet[ICMP].type == 8:
        print("[←] ICMP Echo Request détecté.")
        process_incoming_icmp(packet)
        return

    # 4. Paquet ICMP fragmenté
    if ip_proto == 1 and is_fragment:
        print("[←] Fragment ICMP détecté.")
        process_incoming_icmp(packet)
        return

    print("[!] Paquet IP entrant non-ICMP sans action.")



print(f"[✓] Démarrage du sniffer sur {PRINCIPAL_INTERFACE}...")
sniff(iface=[CANAL_INTERFACE, PRINCIPAL_INTERFACE], prn=packet_callback, store=0)

