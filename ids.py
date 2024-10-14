from scapy.all import IP, TCP, UDP
from protocols import get_protocol_name

class IntrusionDetectionSystem:
    def __init__(self):
        self.ids_playbook = {
            "blacklist_ips": ["192.168.0.105", "10.0.0.5"],
            "suspicious_ports": [22, 23, 3389, 8080],
            "suspicious_protocols": ["HTTP", "FTP", "SSH"]
        }

    def generate_alerts(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if src_ip in self.ids_playbook["blacklist_ips"] or dst_ip in self.ids_playbook["blacklist_ips"]:
                return f"ALERT: Suspicious IP detected - {src_ip} -> {dst_ip}"
        
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
            if port in self.ids_playbook["suspicious_ports"]:
                return f"ALERT: Suspicious Port detected - {port}"
        
        protocol_name = get_protocol_name(packet.sprintf("%IP.proto%")) if packet.haslayer(IP) else "Unknown"
        if protocol_name in self.ids_playbook["suspicious_protocols"]:
            return f"ALERT: Suspicious Protocol detected - {protocol_name}"

        return None
