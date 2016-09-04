#!/usr/bin/env python
# To compile: gcc -o sniffer sniffer.c -l pcap
#
# To run: tcpdump -s0 -w - | ./sniffer -
#     Or: ./sniffer <some file captured from tcpdump or wireshark>

import os
from difflib import Differ

def run():
    print '---------------------------------------------------------------------------'
    test_ipv4()
    test_ipv6()

def test_ipv4():
    test('sample_tcp_IPv4.pcap')
    test('sample_udp_IPv4.pcap')
    test('sample_icmp_IPv4.pcap')

def test_ipv6():
    test('sample_udp_IPv6.pcap')
    test('sample_tcp_IPv6.pcap')
    test('sample_icmp_IPv6.pcap')

def test(name):
    answers = name + '.answer'
    answer = open(answers)
    os.system("gcc -o sniffer sniffer.c -l pcap")
    os.system("./sniffer " + name + " > results.txt");
    results = open('results.txt')
    difference = ''
    for line in Differ().compare(results.readlines(), answer.readlines()):
        if line.startswith(" "):
            continue
        else:
            difference += line
    if difference == '':
        print "PASS: " + name
    else:
        print difference
    print '---------------------------------------------------------------------------'
    os.system("rm results.txt")

if __name__ == '__main__':
    run()
