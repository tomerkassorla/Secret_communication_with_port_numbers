import sys

i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *

sys.stdin, sys.stdout, sys.stderr = i, o, e


def get_ip(response):
    if response[DNS].ancount == 0:
        print "not valid"
    elif response[DNS].ancount == 1:
        print response[DNSRR].rdata
    elif response[DNS].ancount > 1:
        for i in xrange(response[DNS].ancount):
            print response[DNSRR][i].rdata


def main():
    input = raw_input("enter domain")
    print input
    if input[0].isalpha():
        dns_packet = IP(dst="0.0.0.0") / UDP(sport=24601, dport=53) / DNS(qdcount=1, rd=1) / DNSQR(qname=input)
        response = sr1(dns_packet, verbose=0)
        get_ip(response)
    else:
        ip_x = ""
        ip_split = input.split(".")
        for i in xrange(len(ip_split)):
            ip_x += ip_split[-i - 1] + "."
        dns_packet = IP(dst="0.0.0.0") / UDP(sport=24601, dport=53) / DNS(qdcount=1, rd=1) / DNSQR(
            qname=ip_x + "in-addr.arpa",
            qtype="PTR")
        response = sr1(dns_packet, verbose=0)
        print response[DNSRR].rdata


if __name__ == '__main__':
    main()
