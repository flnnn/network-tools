from scapy.all import *

import os


def get_ap_mac(ssid):
    
    def filter_ap(pkt):
        if pkt.haslayer(Dot11Beacon):
            elt = pkt[Dot11Elt]
            if elt.ID == 0 and elt.info.decode() == ssid:
                return pkt

    mac_ap = sniff(
        iface="wlan0",
        lfilter=filter_ap,
        count=1
    )

    return mac_ap[0][Dot11].addr2


def get_handshake():
    
    def filter_eapol(pkt):
        pass
