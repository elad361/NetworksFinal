import socket
from scapy.all import IP, DNS, DNSQR, send, sniff, sr1, UDP, IPv6

HOST = '127.0.0.1'
SPORT = 20649
DPORT = 30649

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
serveradd = (HOST, DPORT)
sock.bind((HOST, SPORT))
sock.sendto('SYN'.encode(), serveradd)
ans, addr = sock.recvfrom(1024)

print("got ans:")
print(ans.decode())

print("sending ACK")
sock.sendto('ACK'.encode(), serveradd)

print("sending req")
sock.sendto('GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'.encode(), serveradd)


ans, addr = sock.recvfrom(1024)
print("got ans:")
print(ans.decode())
ans, addr = sock.recvfrom(1024)
print("got ans:")
print(ans.decode())
print("sending ACK")
sock.sendto('ACK'.encode(), serveradd)

sock.sendto('HELLO'.encode(), serveradd)
ans, addr = sock.recvfrom(1024)
print("ans: ", ans.decode())


