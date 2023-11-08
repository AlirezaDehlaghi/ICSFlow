import pcapy
from scapy.all import *

devs = pcapy.findalldevs()
print("Available network interfaces:")
for dev in devs:
    print(dev)