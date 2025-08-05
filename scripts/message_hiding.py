#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, fragment, UDP
from scapy.layers.l2 import Ether

# --------------------- Cacher un message dans un paquet ICMP ---------------------

def encapsulate_message(message, src_ip, dst_ip, sport, dport, protocole):
    """
    Fonction pour encapsuler un message dans un paquet TCP ou UDP.
    :param message: Le message à encapsuler.
    :param src_ip: Adresse IP source.
    :param dst_ip: Adresse IP de destination.
    :param sport: Port source.
    :param dport: Port de destination.
    :param protocole: Protocole (TCP ou UDP).
    :return: Le paquet encapsulé.
    """
    if protocole == "TCP":
        return Ether()/IP(src=src_ip, dst=dst_ip) / \
               TCP(sport=sport, dport=dport) / \
               Raw(load=message)
    elif protocole == "UDP":
        return Ether()/IP(src=src_ip, dst=dst_ip) / \
               UDP(sport=sport, dport=dport) / \
               Raw(load=message)
    else:
        raise ValueError("Protocole non supporté")

def create_icmp_paquet(encapsulated_packet, fake_source_ip, fake_destination_ip):
    """
    Fonction pour encapsuler un paquet dans une requête ICMP Echo.
    :param message: Le message à cacher.
    :param src_ip: Adresse IP source.
    :param dst_ip: Adresse IP de destination.
    :return: Le paquet ICMP encapsulé.
    """

    ICMP_paquet = IP(src=fake_source_ip, dst=fake_destination_ip) / \
                    ICMP(type=8) / \
                    Raw(load=bytes(encapsulated_packet[IP]))

    # LE PAQUET ICMP N'EST PAS FRAGMENTE

    return ICMP_paquet

def fragmenter_paquet(paquet, taille_fragment):
    """
    Fonction pour fragmenter un paquet ICMP.
    :param paquet: Le paquet à fragmenter.
    :param taille_fragment: Taille maximale de chaque fragment.
    :return: Liste des fragments.
    """
    return fragment(paquet, fragsize=taille_fragment)

def envoyer_fragments(fragments, interface):
    """
    Fonction pour envoyer les fragments sur une interface donnée.
    :param fragments: Liste des fragments à envoyer.
    :param interface: Interface sur laquelle envoyer les fragments.
    """
    for i, frag in enumerate(fragments):
        print(f"Fragment {i+1} - taille : {len(bytes(frag))} octets")
        send(frag, iface=interface)

# --------------------- Défragmenter un paquet ICMP ---------------------

def decapsulate_icmp_message(packet):
    """
    Fonction pour extraire la charge utile d'un paquet ICMP.
    :param packet: Le paquet ICMP à analyser.
    :return: Le message caché, ou None si ce n'est pas un message caché.
    """
    if ICMP in packet and Raw in packet:
        # Extraire la charge utile (payload) de l'ICMP
        payload = bytes(packet[Raw].load)
        print(f"[*] Chargement du paquet ICMP : {payload}")

        # Vérifier si le préfixe "HIDE:" est présent
        if payload.startswith(b"HIDE:"):
            return payload
        else:
            return None
    else:
        return None

