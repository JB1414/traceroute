import re
from ICMPv4Packet import ICMPv4Packet
from ICMPv6Packet import ICMPv6Packet
from Ping import Ping, ResponceInfo


class Traceroute:
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

    def format_info(self, current_ttl, responce_info):
        result = ""
        if not self.is_debug_mode:
            result += str(current_ttl).ljust(6)
            address = responce_info.reciever_address
            times = responce_info.responces_times_miliseconds
            for time in times:
                result += str(time).ljust(6) if time is not None else "*".ljust(6)
            result += address.ljust(
                15) if address is not None else "Timeout exeeded".ljust(15)
        else:
            result += f"Current ttl = {current_ttl}\n"
            address = responce_info.reciever_address
            times = responce_info.responces_times_miliseconds
            if address is None:
                result += "Server didn't respond on requests\n"
                return result
            else:
                result += f"Succesfuly connected to {address}\n"
            for index, time in enumerate(times):
                if time is not None:
                    result += f"Packet {index} was delivered and respond got in {time} ms\n"
                else:
                    result += f"Packet {index} was send to server but respond timeout exeeded\n"
        return result

    def traceroute(self):
        final_destination = self.packet.dst
        previous_address = None
        for ttl in range(1, self.max_ttl + 1):
            packet = self.packet.get_packet(ttl)
            ping = Ping(packet, self.timeout_seconds, self.repeat,
                        self.interval_between_seconds)
            responce_info = ping.do_ping()
            print(self.format_info(ttl, responce_info))
            if final_destination == responce_info.reciever_address or \
                    (previous_address == responce_info.reciever_address and previous_address != None):
                return
            previous_address = responce_info.reciever_address
