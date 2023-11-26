import pytest
import ipaddress
from scapy.all import *
import sys
from unittest.mock import MagicMock, patch
from ICMPv4Packet import ICMPv4Packet
from ICMPv6Packet import ICMPv6Packet
from main import get_packet, check_length, check_timeout, check_interval, check_repeat, check_maxhops
from Ping import Ping, ResponceInfo
import time
from Traceroute import Traceroute


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
        "not_a_real_domain.com",
        "неправильный_домен.прикол"
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
        ("8.8.8.8", 50, 2, 2),
        ('ya.ru', 60, 10, 3)
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


class TestICMPv6Packet:
    @pytest.mark.parametrize("dst, length, seq, ttl", [
        ("2a00:1450:4010:c08::64", 40, 1, 1),
        ("2a02:6b8::2:242", 50, 2, 2)
    ])
    def test_get_packet(self, dst, length, seq, ttl):
        exemplar = ICMPv6Packet(dst, length, seq)
        packet = exemplar.get_packet(ttl)
        packet_dst = packet[IPv6].dst
        packet_ttl = packet[IPv6].hlim
        packet_seq = packet[ICMPv6EchoRequest].seq
        packet_length = len(packet)
        assert dst == packet_dst
        assert ttl == packet_ttl
        assert seq == packet_seq


class TestPing:
    @pytest.mark.parametrize('timeout_seconds, repeat, interval', [
        (1, 3, 1),
        (1, 5, 1)
    ])
    def test_do_ping(self, timeout_seconds, repeat, interval):
        packet = ICMPv4Packet('google.com', 40, 1)
        ping_instance = Ping(packet, timeout_seconds, repeat, interval)
        result = ping_instance.do_ping()
        assert isinstance(result, ResponceInfo)

    @pytest.mark.parametrize('timeout_seconds, repeat, interval', [
        (1, 3, 4),
        (1, 5, 2)
    ])
    def test_do_ping_timings(self, timeout_seconds, repeat, interval):
        packet = ICMPv4Packet('google.com', 40, 1)
        ping_instance = Ping(packet, 1, 4, 3)
        ping_instance.do_ping()
        start_time = time.time()
        result = ping_instance.do_ping()
        end_time = time.time()
        duration = end_time - start_time
        assert duration >= repeat * interval

    @pytest.mark.parametrize("packet_type, packet_code, expected", [
        (11, 0, True),  # Тип и код для TTL превышен
        (0, 0, False)   # Тип и код для успешного ответа
    ])
    def test_is_responce_ttl_exeeded(self, packet_type, packet_code, expected):
        packet = MagicMock()
        packet.type = packet_type
        packet.code = packet_code

        assert Ping.is_responce_ttl_exeeded(packet) == expected

    @pytest.mark.parametrize("packet_type, packet_code, expected", [
        (0, 0, True),   # Тип и код для успешного ответа
        (11, 0, False)  # Тип и код для TTL превышен
    ])
    def test_is_responce_ok(self, packet_type, packet_code, expected):
        packet = MagicMock()
        packet.type = packet_type
        packet.code = packet_code

        assert Ping.is_responce_ok(packet) == expected

    @pytest.mark.parametrize("time_seconds, expected_miliseconds", [
        (1, 1000),
        (0.5, 500)
    ])
    def test_to_miliseconds(self, time_seconds, expected_miliseconds):
        assert Ping.to_miliseconds(time_seconds) == expected_miliseconds


class TracerouteTests:
    @pytest.mark.parametrize("responce_info", [
        (ResponceInfo('0.0.0.0', [None, None, None])),
        (ResponceInfo('127.0.0.1', [1, 1, 1])),
        (ResponceInfo('1.2.3.4', [1, None, None]))
    ])
    def test_format_info(self, responce_info):
        traceroute = Traceroute(None, 1, 1, 1, 1)
        formatted_info = traceroute.format_info(1, responce_info)
        for time in responce_info.responces_times_miliseconds:
            if time != None:
                assert time in formatted_info
            else:
                assert '*' in formatted_info
        if responce_info.reciever_address != None:
            assert responce_info.reciever_address in formatted_info
