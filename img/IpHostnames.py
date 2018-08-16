import socket
from os import system
import requests

try:
	
	with open('ip2.txt', 'r') as file:
		for line in file.readlines():	
			line_ip = line.split('\n')[0]
			#ipv4 = socket.gethostbyname(line_ip)
			host = socket.gethostbyaddr(line_ip)

			print(host[0])
			
			
except Exception,e:
		print('Error: {}'.format(e))
		pass