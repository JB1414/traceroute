from Traceroute import Traceroute
from ICMPv4Packet import *
from ICMPv6Packet import *
import argparse
import re
import ipaddress
import sys
import socket

ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
ipv6_pattern = r'^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$'
domain_name_pattern = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})$'

def get_arguments():
    parser = argparse.ArgumentParser(description="Traces the route to the server")
    parser.add_argument("address", help="The destination adress to traceroute to", type=str)
    parser.add_argument("-l", "--length", help='Set custom length of the packet', type=int, default=40)
    parser.add_argument("-seq", help="Custom SEQ", type=int, default=0)
    parser.add_argument("-t", "--timeout", help="Responce Timeout", type=int, default=1)
    parser.add_argument("-i", "--interval", help="Interval between requests", type=int, default=0)
    parser.add_argument("-r", "--repeat", help="How many times repeat packets to each adress", type=int, default=3)
    parser.add_argument("-mh", "--maxhops", help="Max hops count", type=int, default=30)
    parser.add_argument("-dm", "--debugmode", help="Activates debug mode", action="store_true")
    args = parser.parse_args()
    return args

def get_packet(address, length, seq):
    if re.match(ipv4_pattern, address):
        print("1")
        try:
            ipaddress.ip_address(address)
        except Exception:
            print("Invalid address")
            sys.exit(-1)
        return ICMPv4Packet(address, length, seq)
    elif re.match(ipv6_pattern, address):
        try:
            ipaddress.IPv6Address(address)
        except ipaddress.AddressValueError:
            print("Invalid address")
            sys.exit(-1)
        return ICMPv6Packet(address, length, seq)
    elif re.match(domain_name_pattern, address):
        try:
            ip_address = socket.gethostbyname(address)
        except socket.gaierror:
            print("Invalid address")
            sys.exit(-1)
        return ICMPv4Packet(ip_address, length, seq)
    else: 
        print("Invalid address")
        sys.exit(-1)

def check_length(len):
    if len < 8:
        print(f"The packet length can't be {len}")
        sys.exit(-3)

def check_timeout(timeout):
    if timeout < 0:
        print(f"Timeout can't be negative")
        sys.exit(-2)

def check_interval(interval):
    if interval < 0:
        print(f"Interval can't be negative")

def check_repeat(repeat):
    if repeat < 0:
        print(f"Repeat can't be negative")

def check_maxhops(maxhops):
    if maxhops < 0:
        print(f"Maxhops (TTL) cannot be negative")

def check_arguments(args):
    check_length(args.length)
    check_timeout(args.timeout)
    check_interval(args.interval)
    check_repeat(args.repeat)
    check_maxhops(args.maxhops)

def main():
    args = get_arguments()
    check_arguments(args)
    address = str(args.address)
    packet = get_packet(address, args.length, args.seq)
    tracert = Traceroute(packet, args.timeout, args.interval, args.repeat, args.maxhops, args.debugmode)
    tracert.traceroute()


if __name__ == "__main__":
    main()
