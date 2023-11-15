from Traceroute import Traceroute
from ICMPv4Packet import *

packet = ICMPv4Packet("google.com", 40, 3)
tracert = Traceroute(packet, 1, 0.5, 2, 30).traceroute()
