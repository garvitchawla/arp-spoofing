# arp-spoofing

This program will work just like an arpspoof command line utility in Kali Linux. It'll update the ARP packet sent and you can perform a man in the middle attack by providing a target and router IP. After providing a keyboard Interrupt, the program will Reset the arp tables of the victim and the router.



OUTPUT:


root@kali:~/arp_spoof# python3 arp_spoof.py 

Enter your target IP: 172.16.61.200

Enter your gateway IP: 172.16.61.2

[+] Packets sent: 14^C

[+] Detected Ctrl + C .... Resetting ARP Tables!

All Done!
