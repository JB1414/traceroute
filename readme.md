# Traceroute

##### made by: @VartoSss

---

### Description:

This programm is the implementation of the standart network utility traceroute (tracert in windows). It shows the route of a package from your devise to some server.

---

### Usage:

python main.py [OPTIONS] address

positional arguments:
address The destination adress to traceroute to

options:
-h, --help (show this help message and exit)
-l LENGTH, --length LENGTH (Set custom length of the packet)
-seq SEQ (Custom SEQ)
-t TIMEOUT, --timeout TIMEOUT (Responce Timeout)
-i INTERVAL, --interval INTERVAL (Interval between requests)
-r REPEAT, --repeat REPEAT (How many times repeat packets to each adress)
-mh MAXHOPS, --maxhops MAXHOPS (Max hops count)
-dm, --debugmode (Activates debug mode)

---

### Project structure:

1. ICMPv4Packet and ICMPv6Packet - classes that build ICMP packages of the IP4 and IP6 protocols.
2. Ping - class that make single ping to the server with fixed ttl (time to live) and optional parameters. Creates a small report of a ping to the server if ping was succesful (IP address of a server and responces timings)
3. Traceroute - class that make pings to the destination server with different ttl of a package and formats the answer.
4. main - class that adds parameters for CMD UI and checks them.

---
