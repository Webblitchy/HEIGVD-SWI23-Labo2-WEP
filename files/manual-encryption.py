#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

from scapy.all import *
import binascii
from rc4 import RC4

# Cle wep AA:AA:AA:AA:AA
key = b"\xaa\xaa\xaa\xaa\xaa"

# lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap("arp.cap")[0]

# Définition de notre message en clair
data = bytes.fromhex(
    "aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8deadbeef"
)

# Calcul de l'ICV
icv = binascii.crc32(data)
# Transformation en bytes de l'ICV
icv = icv.to_bytes(4, "little")

# notre plaintext sont les données concaténées avec l'ICV
ptext = data + icv

# le seed RC4 est composé de IV+clé
seed = arp.iv + key

# chiffrement RC4
cipher = RC4(seed, streaming=False)
ctext = cipher.crypt(ptext)

# l'ICV est les derniers 4 octets
icv_encrypted = ctext[-4:]
# On converti dans le bon format (en long) pour le paquet
icv_encrypted = struct.unpack("!L", icv_encrypted)[0]

# Les données sont tout le ciphertext sauf les 4 derniers octets
message_encrypted = ctext[:-4]

print("Text: ", message_encrypted)
print("icv:  ", icv_encrypted)

# On met la length à None pour que Scapy recalcule la longueur de lui-même
arp[RadioTap].len = None

# On affecte le nouveau message chiffré et le nouvel ICV chiffré
arp.wepdata = message_encrypted
arp.icv = icv_encrypted

# On enregistre dans le fichier pcap
wrpcap("manual-encryption.pcap", arp)
