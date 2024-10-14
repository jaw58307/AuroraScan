from scapy.all import sniff

def capture_packets(callback, iface="Wi-Fi", count=0):
    """
    Capture packets on the given interface and pass each packet to the callback function.
    :param callback: Function to process each packet
    :param iface: Network interface to capture packets from
    :param count: Number of packets to capture (0 for infinite)
    """
    sniff(iface=iface, prn=callback, count=count, store=0)
