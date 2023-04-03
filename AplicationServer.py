##########################################################
# Author: Elad Shoham                                    #
# I.D: 205439649                                         #
# A Redirect Server, work both on TCP, and a secured UDP #
##########################################################
import threading
import socket
import time

HOST = '127.0.0.1'
SPORT = 20649
DPORT = 30649
MAX_CLIENTS = 5  # For the UDP server
SERVER_RCV_SIZE = 1024
CLIENT_SEND_BUFF_SIZE = 1024


# Implement the task by using a TCP:
class TCPServer:
    def __init__(self):
        # init the res for redirect
        self.res = b''

    # *****handleClient*************************************
    # input: client connection
    # send the response back for redirecting if a GET req
    def handleClient(self, client):

        recv = client.recv(1024)
        if 'GET' in recv.decode():  # redirect
            print("Received a GET req")
            client.sendall(self.res)
            print("***respond sent back***")
            print("closing socket\n")
            client.close()

        else:
            print("*Not* a GET req")
            print("got:", recv)
            print("closing socket\n")
            client.close()

    # *****run***************************************
    # runs the server
    def run(self):
        # Set the new URL for res
        newURL = input("new URL: ")
        self.res = 'HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\n\r\n'.format(newURL).encode()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # set address
            address = ('', DPORT)
            # bind socket
            sock.bind(address)
            print("Server bound")
            print("Port: {}".format(DPORT))
            sock.listen()
            print("Listening...")
            while True:
                cl, clAddr = sock.accept()
                print("\n***New connection***")
                print("From:", clAddr)
                print("handling...\n")
                self.handleClient(cl)


class ReliableUDPServer:
    # *****Client*********************************************
    # Represent a client that connected to our server
    # We need to save client address for a reliable connection
    class Client:
        def __init__(self, addr):
            self.addr = addr
            self.windowSize = 2  # to start with
            self.currentAck = 0
            self.ack = False
            self.numOfTries = 0

        def send(self, sock, data):
            """
            recursive func, send to the client a msg, if time passed and didn't get ack, send again
            :param sock: to send from
            :param data: to send
            :return: void
            """
            sock.sendto(data.encode(), self.addr)
            time.sleep(1)
            # didn't get ack, send again
            if (not self.ack) and self.numOfTries < 5:  # if we tried 5 times, stop trying
                self.numOfTries += 1
                self.send(sock, data)

        def sendACK(self, sock):
            """
            Sends an ack
            :param sock: to send from
            :return: void
            """
            sock.sendto('ACK'.encode(), self.addr)

    # Initialize a socket for our server
    # Also initialize some other helpers vars
    def __init__(self):
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.clientsLim = 5
        self.clients = {}
        # init the res for redirect
        self.res = b''

    def bind(self, address):
        """
        Bind our socket to an address
        :param address: to bind to
        :return: void
        """
        self.sock.bind(address)

    def listen(self):
        """
        Listen and serve clients
        :return: void
        """
        msg, addr = self.sock.recvfrom(SERVER_RCV_SIZE)
        print("\nReceived a new msg:\n" + msg.decode())
        if addr in self.clients:
            if 'ACK' in msg.decode():
                self.clients[addr].ack = True
            elif 'GET' in msg.decode():
                self.clients[addr].sendACK(self.sock)
                # send redirect msg:
                self.clients[addr].numOfTries = 0
                self.clients[addr].ack = False  # we sent a new msg that need to be ack
                th = threading.Thread(target=self.clients[addr].send, args=(self.sock, self.res))
                # self.clients[addr].send(self.socket, self.res)
                th.start()
                self.clients.pop(addr)

        else:  # got a new connection
            succeed = False
            counter = 0
            # If we tried too many times, close connection
            while counter < 5:
                # for flow control, we don't want to connect too many clients
                if len(self.clients) < self.clientsLim:
                    if 'SYN' in msg.decode():
                        # make a 3 way handshake
                        newC = self.Client(addr)
                        th = threading.Thread(target=newC.send, args=(self.sock, 'SYN, ACK'))
                        th.start()
                        # newC.send(self.socket, 'SYN, ACK')
                        succeed = True
                        self.clients[addr] = newC
                        self.clientsLim += 1  # we can handle more...
                        break
                    else:
                        # we first need to handshake (by the protocol)
                        print("Not SYN!")
                        self.sock.sendto('Client did not SYN, Closing connection...'.encode(), addr)
                        succeed = True
                        break

                else:  # we still have too many clients
                    counter += 1
                    time.sleep(0.1)

            if not succeed:
                self.sock.sendto('Too many connection on server, pls try again later. Closing connection...'.encode(),
                                 addr)
                if self.clientsLim > 1:
                    self.clientsLim -= 1

    def run(self):
        """
        Run the server
        :return: void
        """
        newURL = input("new URL: ")
        self.res = 'HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\n\r\n'.format(newURL)
        print("\nBinding to socket")
        print("host: {}, port: {}".format(HOST, DPORT))
        self.sock.bind((HOST, DPORT))
        while True:
            self.listen()


print("***HTTP Redirect Server***\nhost address: {}, port: {}".format(HOST, DPORT))
option = input("choose connection:\n1 -> for TCP\n2 -> for Reliable UDP\n")
if option == '1':
    server = TCPServer()

else:
    server = ReliableUDPServer()
server.run()
