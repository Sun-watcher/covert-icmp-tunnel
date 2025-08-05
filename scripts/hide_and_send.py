from message_hiding import *

# Taille du fragment ICMP
PAYLOAD_ICMP_SIZE = 20

# Table de correspondance des adresses (permet d'interchanger
# automatiquement les adresses sources et destinations réelles et cachées)
ADDRESS_MAPPING = {
    "10.87.87.1": "192.168.10.1",
    "10.87.87.2": "192.168.20.1",
    "192.168.10.1": "10.87.87.1",
    "192.168.20.1": "10.87.87.2"
}

INTERFACE_MAPPING = {
    "10.87.87.1": "h1-injection",
    "10.87.87.2": "h2-injection",
}

def hide_message_in_icmp(message, src_ip, dst_ip, sport, dport, protocole):
    """
    Fonction principale pour cacher un message dans un paquet ICMP.
    :param message: Le message à cacher.
    :param src_ip: Adresse IP source.
    :param dst_ip: Adresse IP de destination.
    :param sport: Port source.
    :param dport: Port de destination.
    :param protocole: Protocole (TCP ou UDP).
    """

    try :
        # Encapsuler le message dans un paquet TCP ou UDP
        packet = encapsulate_message(message, src_ip, dst_ip, sport, dport, protocole)
        print("Message encapsulé dans le paquet : ", packet.show())
    except Exception as e:
        print("Erreur lors de l'encapsulation du message : ", e)
        return

    # Créer le paquet ICMP

    fake_source_ip = ADDRESS_MAPPING[src_ip]
    fake_destination_ip = ADDRESS_MAPPING[dst_ip]

    try :
        icmp_packet = create_icmp_paquet(packet, fake_source_ip, fake_destination_ip)
        print("Paquet ICMP créé : ", icmp_packet.show())
    except Exception as e:
        print("Erreur lors de la création du paquet ICMP : ", e)
        return

    # Fragmenter le paquet ICMP
    try:
        fragments = fragmenter_paquet(icmp_packet, PAYLOAD_ICMP_SIZE)
        print("Paquet ICMP fragmenté : ", fragments)
    except Exception as e:
        print("Erreur lors de la fragmentation du paquet ICMP : ", e)
        return

    # Envoyer les fragments sur l'interface de destination

    targeted_interface = INTERFACE_MAPPING[src_ip]

    try:
        envoyer_fragments(fragments, targeted_interface)  # Remplacez par l'interface appropriée
    except Exception as e:
        print("Erreur lors de l'envoi des fragments : ", e)
        return