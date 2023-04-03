import socket

HOST = '127.0.0.1'
SPORT = 20649
DPORT = 30649

sock = socket.socket()
sock.bind(('0.0.0.0', SPORT))
sock.connect((HOST, DPORT))
sock.send('GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'.encode())
ans = sock.recv(1024)
print(ans.decode())
