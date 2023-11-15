from scapy.all import *

conf.verb = 0
def is_responce_ttl_exeeded(packet : ICMP):
    return packet.type == 11 and packet.code == 0

for ttl in range(30):
    pack = IP(dst="google.com", ttl=ttl)/ICMP()
    responce = sr1(pack, timeout=1)
    if responce is not None and is_responce_ttl_exeeded(responce):
        sender_ip = responce.getlayer(IP).src
        print(sender_ip)
    else: continue


