from scapy.all import ICMPv6EchoRequest, IPv6, RandString

class ICMPv6Packet:
    def __init__(self,
                 dst: str,
                 length: int,
                 seq: int):
        self.dst = dst
        self.length = length
        self.seq = seq
        
    def get_packet(self, ttl):
        random_payload = str(RandString(self.length - 8))
        return IPv6(dst=self.dst, ttl=ttl) / ICMPv6EchoRequest(seq=self.seq) / random_payload