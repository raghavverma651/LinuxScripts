#!/usr/bin/python3
import scapy.all as scapy
import os
import sys
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
 
    return answered_list[0][1].hwsrc
 
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
 
def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print("Unauthenticated changes detected in ARP Table - \n")
                os.system("cat /proc/net/arp")
                print("\n")
    os.system(“chmod 777 /proc/net/arp”)
                print("Updated ARP Table - \n")
                os.system("sudo cp /root/Downloads/validarp /proc/net/arp ")
    os.system("cat /proc/net/arp")
                print("ARP Spoofing Mitigated....\n")
                print("Attacker MAC: ",real_mac)
                sys.exit()
        except IndexError:
            pass
#Specifically eth0 here due to simulated physical connections in VMware
sniff("eth0") 

