from scapy.all import IP, DNS, DNSQR, send, sniff, sr1, UDP, IPv6, DNSRR
SPORT = 20649
DPORT = 30649

req = IP(dst='127.0.0.1')/UDP(sport=SPORT, dport=DPORT)/DNS(rd=1, qd=DNSQR(qname="www.google.com"))
print("sending req:")
print(req.show())
resp = sr1(req, verbose=0)
print("got response!")
