class PacketInfo:
    TYPE_IP = "IP"  # Internet Protocol (IPv4)
    TYPE_ARP = "ARP"  # Address Resolution Protocol
    TYPE_IPv6 = "IPv6"  # Internet Protocol (IPv6)
    TYPE_IPX = "IPX"  # Internetwork Packet Exchange
    TYPE_VLAN = "VLAN"  # IEEE 802.1Q (VLAN tagging)
    TYPE_PPP = "PPP"  # Point-to-Point Protocol
    TYPE_MPLS = "MPLS"  # Multiprotocol Label Switching
    TYPE_MPLS = "MPLS"  # MPLS with downstream-assigned label
    TYPE_PPPoE = "PPPoE"  # PPP over Ethernet (Discovery stage)
    TYPE_PPPoE = "PPPoE"  # PPP over Ethernet (Session stage)
    TYPE_QinQ = "QinQ"  # 802.1ad (Q-in-Q VLAN tagging)
    TYPE_Realtek = "Realtek"  # Realtek protocol
    TYPE_LLDP = "LLDP"  # Link Layer Discovery Protocol
    TYPE_FCoE = "FCoE"  # Fibre Channel over Ethernet
    TYPE_FCoE = "FCoE"  # FCoE Initialization Protocol

    # Define packet types (Ethertypes)
    TYPES = {
        0x0800: TYPE_IP,  # Internet Protocol (IPv4)
        0x0806: TYPE_ARP,  # Address Resolution Protocol
        0x86DD: TYPE_IPv6,  # Internet Protocol (IPv6)
        0x8137: TYPE_IPX,  # Internetwork Packet Exchange
        0x8100: TYPE_VLAN,  # IEEE 802.1Q (VLAN tagging)
        0x880B: TYPE_PPP,  # Point-to-Point Protocol
        0x8847: TYPE_MPLS,  # Multiprotocol Label Switching
        0x8848: TYPE_MPLS,  # MPLS with downstream-assigned label
        0x8863: TYPE_PPPoE,  # PPP over Ethernet (Discovery stage)
        0x8864: TYPE_PPPoE,  # PPP over Ethernet (Session stage)
        0x88A8: TYPE_QinQ,  # 802.1ad (Q-in-Q VLAN tagging)
        0x8899: TYPE_Realtek,  # Realtek protocol
        0x88CC: TYPE_LLDP,  # Link Layer Discovery Protocol
        0x8906: TYPE_FCoE,  # Fibre Channel over Ethernet
        0x8914: TYPE_FCoE,  # FCoE Initialization Protocol
    }

    PROTOCOL_ICMP = "ICMP"  # Internet Control Message Proto
    PROTOCOL_IGMP = "IGMP"  # Internet Group Management Prot
    PROTOCOL_TCP = "TCP"  # Transmission Control Protocol
    PROTOCOL_UDP = "UDP"  # User Datagram Protocol
    PROTOCOL_IPv6 = "IPv6"  # IPv6 encapsulation
    PROTOCOL_GRE = "GRE"  # Generic Routing Encapsulation
    PROTOCOL_ESP = "ESP"  # Encapsulating Security Payload
    PROTOCOL_AH = "AH"  # Authentication Header
    PROTOCOL_ICMPv6 = "ICMPv6"  # Internet Control Message Pr
    PROTOCOL_OSPF = "OSPF"  # Open Shortest Path First
    PROTOCOL_SCTP = "SCTP"  # Stream Control Transmission
    PROTOCOL_MPLS = "MPLS"  # MPLS-in-IP
    PROTOCOL_FCoE = "FCoE"  # Fibre Channel over Ethernet

    # Define IP-based protocols
    PROTOCOLS = {
        1: PROTOCOL_ICMP,  # Internet Control Message Protocol
        2: PROTOCOL_IGMP,  # Internet Group Management Protocol
        6: PROTOCOL_TCP,  # Transmission Control Protocol
        17: PROTOCOL_UDP,  # User Datagram Protocol
        41: PROTOCOL_IPv6,  # IPv6 encapsulation
        47: PROTOCOL_GRE,  # Generic Routing Encapsulation
        50: PROTOCOL_ESP,  # Encapsulating Security Payload
        51: PROTOCOL_AH,  # Authentication Header
        58: PROTOCOL_ICMPv6,  # Internet Control Message Protocol for IPv6
        89: PROTOCOL_OSPF,  # Open Shortest Path First
        132: PROTOCOL_SCTP,  # Stream Control Transmission Protocol
        137: PROTOCOL_MPLS,  # MPLS-in-IP
        138: PROTOCOL_FCoE,  # Fibre Channel over Ethernet
    }

    @classmethod
    def get_packet_type(cls, eth_type):
        if eth_type in cls.TYPES:
            return cls.TYPES[eth_type]
        else:
            return f'{hex(eth_type)}'

    @classmethod
    def get_packet_protocol(cls, protocol):
        if protocol in cls.PROTOCOLS:
            return cls.PROTOCOLS[protocol]
        else:
            return f'{protocol}'
