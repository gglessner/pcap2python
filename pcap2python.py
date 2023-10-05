#!/usr/bin/env python3

import pyshark
import binascii
import argparse

def hex_to_binary(payload):
	payload = payload.replace(':','')
	binary_payload = binascii.unhexlify(payload)
	return(binary_payload)

def print_preamble(target_host, target_port):
	text = """#!/usr/bin/env python3

import socket
import time
import argparse

target_host = '%s'
target_port = %s
	"""
	print(text % (target_host, target_port))

def print_postamble():
	text = """
def connect_server(target_host, target_port):
	print("TCP Connection: ", target_host, " Port: ", str(target_port))
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((target_host, target_port))
	return(client)

def send_receive(client_sock, message):
	print("\\nSend: ", message)
	client_sock.send(message)
	response = client_sock.recv(4096)
	print("\\nResponse: ", response)

	"""
	print(text)

def main():
	in_connection = 0
	connection_num = 0
	last_was_payload = 0

	parser = argparse.ArgumentParser(description='Script with optional arguments')
	parser.add_argument('-f', '--filename', help='Name of the PCAP file')
	parser.add_argument('-s', '--source-ip', help='Source IP address')
	parser.add_argument('-d', '--destination-ip', help='Destination IP address')
	parser.add_argument('-p', '--destination-port', help='Destination TCP port')

	args = parser.parse_args()

	if not all(vars(args).values()):
		parser.print_usage()
		return
	
	filename = args.filename
	source_ip = args.source_ip
	destination_ip = args.destination_ip
	destination_port = args.destination_port

	print_preamble(destination_ip, destination_port)

	cap = pyshark.FileCapture(filename)

	for pkt in cap:
		if 'TCP' in pkt and 'IP' in pkt:
			if pkt.ip.src == source_ip:
				if pkt.tcp.flags == '0x0002': # SYN
					connection_num = connection_num + 1
					last_was_payload = 0
					if in_connection == 1:
						print("]")
					print("messages%d = [" % connection_num, end='')
					in_connection = 1
					need_tab = 0
				if pkt.tcp.flags == '0x0018': # PUSH+ACK
					if in_connection:
						if last_was_payload:
							print(",")
						try:
							if need_tab == 0:
								need_tab = 1
							else:
								print("\t", end='')
							print(hex_to_binary(pkt.tcp.payload), end='')
							last_was_payload = 1
						except AttributeError:
							print("No payload")
	print("]")
	print_postamble()
	for x in range(connection_num):
		print("client = connect_server(target_host, target_port)")
		print("for message in messages%d:" % (x + 1))
		print("\tsend_receive(client, message)")
		print("time.sleep(5)")
		print("client.close()\n")

if __name__ == "__main__":
	main()
