import sys

i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *

sys.stdin, sys.stdout, sys.stderr = i, o, e


def filter_udp(packet):
    return UDP in packet and packet[UDP].dport == 1234


def main():
    input = raw_input("enter what to send")
    for i in xrange(len(input)):
        udp_packet = IP(dst="127.0.0.1") / UDP(sport=1234, dport=ord(input[i]))
        send(udp_packet, verbose=0)
        sniff(count=1, lfilter=filter_udp)


if __name__ == '__main__':
    main()
