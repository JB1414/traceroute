import re
from ICMPv4Packet import ICMPv4Packet
from ICMPv6Packet import ICMPv6Packet
from Ping import Ping, ResponceInfo

class Traceroute:
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$'
    domain_name_pattern = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})$'

    def __init__(self,
                 packet: ICMPv4Packet | ICMPv6Packet,
                 timeout_seconds: int,
                 interval_between_seconds: int,
                 repeat: int,
                 max_ttl: int,
                 is_debug_mode: bool = False):
        self.packet = packet
        self.timeout_seconds = timeout_seconds
        self.interval_between_seconds = interval_between_seconds
        self.repeat = repeat
        self.max_ttl = max_ttl
        self.is_debug_mode = is_debug_mode

    def traceroute(self):
        final_destination = self.packet.dst
        for ttl in range(1, self.max_ttl + 1):
            packet = self.packet.get_packet(ttl)
            ping = Ping(packet, self.timeout_seconds, self.repeat, self.interval_between_seconds)
            responce_info = ping.do_ping()
            print(responce_info)
            if final_destination == responce_info.reciever_address:
                break
            