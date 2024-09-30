"""
Deauth Detector é uma ferramenta de vigilância de rede wi-fi
para detecção de ataques Deauth.

Com o poder da biblioteca Scapy, consegue realizar o monitormaneto
de forma fácil.

Para o uso desta ferramenta, é necessário um adaptador wi-fi com
capacidade de monitoramento.
"""

from scapy.all import *

deauth_detected = False

def detect_deauth_packets(pkt):
    global deauth_detected
    if pkt.haslayer(Dot11Deauth):
        attack_source = pkt[Dot11].addr2
        attack_destination = pkt[Dot11].addr1

        if not deauth_detected:
            print("Deauthentication Attack Detected! Starting Logging...")
            deauth_detected = True

        print(f"Attacker [{attack_source}]  ------->  Target [{attack_destination}]")


sniff(iface="wlan0", prn=detect_deauth_packets, store=False)
