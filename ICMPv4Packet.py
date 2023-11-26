from scapy.all import IP, ICMP, RandString


class ICMPv4Packet:
    def __init__(self, dst: str, length: int, seq: int):
        self.dst = dst
        self.length = length
        self.seq = seq

    def get_packet(self, ttl):
        random_payload = str(RandString(self.length - 28))
        return IP(dst=self.dst, ttl=ttl) / ICMP(seq=self.seq) / random_payload
