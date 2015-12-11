# -*- coding: utf-8 -*-
import queue
import socket
import sys
import threading

class ChatServer:
    GREETING = b"GREETING"
    MESSAGE = b"MESSAGE"
    INCOMING = b"INCOMING"
    
    def __init__(self, port_in, port_out=10001, dmax=8192):
        """ Initialize a chat server instance
        port_in: the port to expect client messages on
        port_out: optional argument to specify the port used to send messages
                  to the clients
        dmax: optional argument to specify the maximum data size for an
              incoming packet
        """
        self.DATA_MAX = dmax

        self.port_out = int(port_out)
        self.port_in = int(port_in)
        self.clients = {}
        self.socket_in = None
        self.socket_out = None
        self.incoming_queue = None
        self.incoming_thread = None

    def start(self):
        """
        initialize the server sockets, the queue, and the incoming_thread

        attempts to deal with socket issues by decrementing the port used
        """
        try:
            # initialize incoming socket and threads
            self.socket_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                           socket.IPPROTO_UDP)
            self.socket_in.bind(('', self.port_in))
            
            # initialize outgoing socket
            ############################
            # the same socket will be used for all outgoing datagrams
            self.socket_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                            socket.IPPROTO_UDP)
            self.socket_out.bind(('', self.port_out))
            
            # set up the incoming thread and associated data structures
            self.incoming_queue = queue.Queue()
            self.incoming_thread = threading.Thread(target=self.wait_for_message,
                                                    name="incoming_thread")
        except OSError:
            self.port = self.port - 1

        print("Server Initialized")

    def recv_data(self):
        """
        receive data on self.socket_in
        """
        return self.socket_in.recvfrom(self.DATA_MAX)

    def send_data(self, data, address):
        """
        send data from self.socket_out
        """
        self.socket_out.sendto(data, address)

    def handle_exception(self, exception):
        """
        print an exception to the stderr
        """
        print(str(exception), file=sys.stderr)

    def handle_continuation(self, sender_hash, sender, data):
        """
        handler for data starting with self.MESSAGE

        sets up the outgoing message for the clients to receive and then
        delegates it to self.handle_outgoing
        """
        if not data.startswith(self.MESSAGE):
            raise Exception("Client sent misformed data... Ignoring")

        outgoing = self.INCOMING + b"<From " + sender[0].encode() + b":"
        outgoing += str(sender[1]).encode() + b">: " + data[len(self.MESSAGE):]
        self.handle_outgoing(outgoing, sender_hash)

    def handle_outgoing(self, message, sender_hash):
        """
        send a message to everyone in self.clients except for item matching
        sender_hash
        """
        for peer_hash, peer_address in self.clients.items():
            if peer_hash == sender_hash:
                continue
            self.send_data(message, peer_address)

    def register_greeting(self, peer_hash, peer, data):
        """
        register the new client or raise an exception if self.GREETING was
        not the start of the data
        """
        if data.startswith(self.GREETING):
            self.clients[peer_hash] = peer
        else:
            raise Exception("Unexpected message from unregistered peer")

    def handle_incoming(self):
        """
        ***BLOCKING***
        wait for new messages in self.incoming_queue.

        when a new message is available, do some organization and then dispatch
        it to the appropriate handling function

        this is meant to be used in a dedicated thread to avoid hang ups.
        """
        # block until some message queued
        while True:
            try:
                # block until incoming_queue has pending data
                data = self.incoming_queue.get()
                peer = data[1]
                peer_hash = hash(peer)
                content = data[0]
                if self.clients.get(peer_hash) is not None:
                    self.handle_continuation(peer_hash, peer, content)
                else:
                    self.register_greeting(peer_hash, peer, content)
            except Exception as e:
                self.handle_exception(e)

    def wait_for_message(self):
        """
        ***BLOCKING***
        wait to receive data and then add it to self.incoming_queue for
        processing.

        this is meant to be used in a dedicated thread to avoid hang ups.
        """
        while True:
            try:
                # block until data is received and then add it to the queue
                self.incoming_queue.put(self.recv_data())
            except Exception as e:
                self.handle_exception(e)

def parse_args():
    """
    read the CL arguments and use them as parameters for a new ChatServer.
    then start the ChatServer
    """
    if not len(sys.argv) == 3:
        print("Invalid program arguments", file=sys.stderr)
        sys.exit(1)

    server = ChatServer(sys.argv[2])
    server.start()
    server.incoming_thread.start()

    # no reason to spawn an additional thread since the main thread isn't
    # doing anything anyway
    server.handle_incoming()

# main guard
if __name__ == "__main__":
    parse_args()
