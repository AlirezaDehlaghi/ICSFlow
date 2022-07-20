from scapy.all import *
from scapy.layers.l2 import ARP, Ether

response = ""


def discovery(dst, time):
    global response
    ethernet_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_layer = ARP(pdst=dst)
    ans, unans = srp(ethernet_layer / arp_layer, timeout=int(time))

    for sent, received in ans:
        response = response + received[ARP].psrc + " " + received[ARP].pdst + " " + received[ARP].hwsrc + " " + received[ARP].hwdst + " "

    return response

print(discovery("",250))