"""
Rawgex é uma ferramenta de filtragem de tráfego HTTP :)

A filtragem é alcançada por meio de expressão regular.

Obs: ferramenta criada como prova de conceito para demonstrar
a insegurança de dados de login trafegados em comunicação não
criptografada.

*-* Usa a biblioteca Scapy <3
"""

from scapy.all import *
from functools import partial

import argparse
import re

def banner():
    banner  = "--- - -   ---- - - - -\n"
    banner += "------ -- -------- -- ----------- ---\n"
    banner += "\t--- -- --- -\n"
    banner += r"__________                 ________               " + "\n"
    banner += r"\______   \_____ __  _  __/  _____/  ____ ___  ___" + "\n"
    banner += r" |       _/\__  \\ \/ \/ /   \  ____/ __ \\  \/  /" + "\n"
    banner += r" |    |   \ / __ \\     /\    \_\  \  ___/ >    < " + "\n"
    banner += r" |____|_  /(____  /\/\_/  \______  /\___  >__/\_\\ " + "\n"
    banner += r"        \/      \/               \/     \/      \/" + "\n"
    banner += "\n HTTP Filtering Tool\n"
    return banner


def filter_raw(pkt, method="GET", regex=""):
    if pkt.haslayer(Raw):
        raw_load = pkt[Raw].load
        if method.encode() in raw_load:
            regex_match = re.search(regex, raw_load.decode(errors="replace"))
            if regex_match:
                for group in regex_match.groups():
                    print(" |-", group)
                print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--method", help="A method used in the load filtering")
    parser.add_argument("--regex", help="The regex to used in the load filtering")
    parser.add_argument("--interface", required=True, help="The interface to listen on")

    args = parser.parse_args()
    partial_filter_raw = partial(filter_raw, method=args.method, regex=args.regex)

    print(banner())

    sniff(iface=args.interface, prn=partial_filter_raw)
