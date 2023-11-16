from scapy.all import ICMP, sr1, ICMPv6EchoRequest, IP
from time import sleep
from collections import namedtuple

ResponceInfo = namedtuple("ResponceInfo", ["reciever_address", "responces_times_miliseconds"])

class Ping:
    def __init__(self, 
                 packet: ICMP | ICMPv6EchoRequest,
                 timeout_seconds: int,
                 repeat: int,
                 interval_between_seconds: int):
        self.packet = packet
        self.timeout_seconds = timeout_seconds
        self.repeat = repeat
        self.interval_between_seconds = interval_between_seconds

    @staticmethod
    def is_responce_ttl_exeeded(packet : ICMP):
        return packet.type == 11 and packet.code == 0
    
    @staticmethod
    def is_responce_ok(packet: ICMP):
        return packet.type == 0 and packet.code == 0
    
    @staticmethod
    def to_miliseconds(time_seconds): return time_seconds * 1000

    @staticmethod
    def get_organisation_info(address, ttl):
        IPWhois(address).lookup_whois()['nets'][1]['description'] if ttl != 1 else "local"

    def do_ping(self) -> ResponceInfo:
        reciever_address = None
        responces_times_miliseconds = []
        for i in range(self.repeat):
            responce = sr1(self.packet, timeout=self.timeout_seconds, verbose=0)
            if responce is not None:
                responce_time_miliseconds = Ping.to_miliseconds(responce.time - self.packet.sent_time)
                responces_times_miliseconds.append(round(responce_time_miliseconds))
                reciever_address = responce[IP].src
            else:
                responces_times_miliseconds.append(None)

            sleep(self.interval_between_seconds)
        return ResponceInfo(reciever_address, responces_times_miliseconds)



