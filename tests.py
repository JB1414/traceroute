import pytest
import ipaddress
from scapy.all import *
import sys
from unittest.mock import MagicMock, patch
from ICMPv4Packet import ICMPv4Packet
from ICMPv6Packet import ICMPv6Packet
from main import get_packet, check_length, check_timeout, check_interval, check_repeat, check_maxhops
from Ping import Ping, ResponceInfo

class TestGetPacket:
    @pytest.mark.parametrize("address, expected_type", [
        ("192.168.1.1", ICMPv4Packet),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", ICMPv6Packet),
        ("example.com", ICMPv4Packet),
        ("ya.ru", ICMPv4Packet),
        ("2a00:1450:4010:c08::64", ICMPv6Packet),
        ('8.8.8.8', ICMPv4Packet)
    ])
    def test_valid_addresses(self, address, expected_type):
        packet = get_packet(address, 100, 1)
        assert isinstance(packet, expected_type)

    @pytest.mark.parametrize("address", [
        "invalid_ip",
        "999.999.999.999",
        "2001:0db8:85a3::8a2e:0370:7334g",
        "not_a_real_domain.com"
    ])
    def test_invalid_addresses(self, address):
        with pytest.raises(SystemExit) as exc_info:
            get_packet(address, 40, 1)
        assert exc_info.type == SystemExit
        assert exc_info.value.code == -1 


class TestValidations:
    @pytest.mark.parametrize("length", [1, 7])
    def test_check_length_negative(self, length):
        with pytest.raises(SystemExit) as exc_info:
            check_length(length)
        assert exc_info.type == SystemExit
        assert exc_info.value.code == -3

    @pytest.mark.parametrize("timeout", [-1, -10])
    def test_check_timeout_negative(self, timeout):
        with pytest.raises(SystemExit) as exc_info:
            check_timeout(timeout)
        assert exc_info.type == SystemExit
        assert exc_info.value.code == -2

    @pytest.mark.parametrize("interval", [-1, -10])
    def test_check_interval_negative(self, interval):
        with pytest.raises(SystemExit) as exc_info:
            check_interval(interval)
        assert exc_info.type == SystemExit
        assert exc_info.value.code == -1

    @pytest.mark.parametrize("repeat", [-1, -10])
    def test_check_repeat_negative(self, repeat):
        with pytest.raises(SystemExit) as exc_info:
            check_repeat(repeat)
        assert exc_info.type == SystemExit
        assert exc_info.value.code == -1

    @pytest.mark.parametrize("maxhops", [-1, -10])
    def test_check_maxhops_negative(self, maxhops):
        with pytest.raises(SystemExit) as exc_info:
            check_maxhops(maxhops)
        assert exc_info.type == SystemExit
        assert exc_info.value.code == -1


class TestICMPv4Packet:
    @pytest.mark.parametrize("dst, length, seq, ttl", [
        ("google.com", 40, 1, 1),
        ("8.8.8.8", 50, 2, 2)
    ])
    def test_get_packet(self, dst, length, seq, ttl):
        exemplar = ICMPv4Packet(dst, length, seq)
        packet = exemplar.get_packet(ttl)
        packet_dst = packet[IP].dst
        packet_ttl = packet[IP].ttl
        packet_seq = packet[ICMP].seq
        packet_length = len(packet)
        assert dst == packet_dst
        assert ttl == packet_ttl
        assert seq == packet_seq
        assert length == packet_length

