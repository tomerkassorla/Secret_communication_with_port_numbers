import sys

i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *

sys.stdin, sys.stdout, sys.stderr = i, o, e

def filter_udp(packet):
    return UDP in packet and packet[UDP].sport == 1234


def main():
    msg = ""
    while True:
        response = sniff(count=1, lfilter=filter_udp)
        y = response[0][UDP].dport
        msg += chr(y)
        udp_packet = IP(dst="127.0.0.1") / UDP(sport=y, dport=1234)
        send(udp_packet, verbose=0)
        print msg


if __name__ == '__main__':
    main()
