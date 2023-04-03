##########################
# Author: Elad Shoham    #
# I.D: 205439649         #
# A DNS Local Server     #
##########################
import scapy
from scapy.all import IP, DNS, DNSQR, send, sniff, sr1, UDP, IPv6, DNSRR
from datetime import datetime  # for calculating *Time To Live*
import socket
from dnslib import DNSRecord

records = {}  # of requested IP's
PORT = 30649

# get the local IP address of the server
# MY_IP = input("My IP: ")
MY_IP = "127.0.0.1"
print("ip: " + MY_IP)


def forwardDNS(que):
    """
    sends the req to Google DNS (8.8.8.8) and sends the ans back after adding to cache
    :param que: the query
    :return: void
    """
    print("\nGenerating DNS req packet")
    # generating the packet:
    req = IP(dst='8.8.8.8') / UDP(sport=PORT) / DNS(rd=1, qd=DNSQR(qname=que[:-1]))
    print("\npacket generated:")
    print(req.show())

    ans = None
    while not (type(ans) is IP and DNSRR in ans):  # sometimes gets None
        # send req
        ans = sr1(req, verbose=0, timeout=2)

    print("\n*got response*")
    print(ans.summary())

    # build res pkt:
    print("Building pack to send back...")

    # Add the res to the cache
    print("\nadding {} to the cache".format(que))
    records[que] = (ans[DNS], datetime.now())
    # Add the res to the cache
    ipres = ans[DNSRR].rdata


# EOF forwardDNS

def handleDNSReq(query, claddr):

    """
    checks if the req is in cache? send res using cache : forwarding the req
    :param claddr: The clients address
    :param query: the query
    :return: void
    """

    print("\n\n***Sniffed a new DNS req***")
    print("the req: ")
    print(query)
    cip, cport = claddr
    # check if the req already exist in the cache:
    if query in records:  # send res
        print("req: {} is in records".format(query))

        # get the packet and arrival time (to calculate ttl) from cache
        res, origTime = records[query]
        timePassed = (datetime.now() - origTime).total_seconds()  # from recieving the pack
        print("res from cache:")
        print(res.show())
        # check if ttl not passed
        if timePassed <= res["DNS Resource Record"].ttl:
            print("TTL not passed, left: {}".format(res["DNS Resource Record"].ttl - timePassed))

            print("generating response")
            resPac = IP(dst=cip) / UDP(dport=cport, sport=PORT) / res

            # update ttl
            newTtl = int(resPac["DNS Resource Record"].ttl - timePassed)
            resPac["DNS Resource Record"].ttl = newTtl

            print("\npack generated:")
            print(resPac.summary())

            # send back
            send(resPac, verbose=0)
            print("***sent***")
            return

        else:  # ttl passed
            print("TTL passed, forwarding req")
            records.pop(query)  # pop from cache

    forwardDNS(query)
    res, origTime = records[query]
    ans = IP(dst=cip)/UDP(dport=cport, sport=PORT) / res
    print(ans.show())
    send(ans, verbose=0)
# EOF handleDNSReq



"""
I wold do it with a thread, but the request was to build ourself the pockets so i used scapy which is snipping 
but not listening on a socket so you cant run a server that way (even udp needs at least an existing address)
that's why i closed the socket every time, handled a client and opened it again on the next loop
"""

while True:
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.bind((MY_IP, PORT))
    data, addr = sock.recvfrom(1024)
    dns_data = data[12:]
    dns_question = str(DNSRecord.parse(data).get_q().qname)
    sock.close()
    handleDNSReq(dns_question, addr)

