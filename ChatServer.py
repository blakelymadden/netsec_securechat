import queue
import socket
import sys
import threading

class ChatServer:
    GREETING = b"GREETING"
    MESSAGE = b"MESSAGE"
    INCOMING = b"INCOMING"
    
    def __init__(self, port_in, port_out=10001, dmax=8192):
        self.DATA_MAX = dmax

        self.port_out = int(port_out)
        self.port_in = int(port_in)
        self.clients = {}
        self.socket_in = None
        self.socket_out = None
        self.incoming_queue = None
        self.incoming_thread = None

    def start(self):
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
        print("Server Initialized")

    def recv_data(self):
        return self.socket_in.recvfrom(self.DATA_MAX)

    def send_data(self, data, address):
        self.socket_out.sendto(data, address)

    def handle_exception(self, exception):
        print(str(exception), file=sys.stderr)

    def handle_continuation(self, sender_hash, sender, data):
        if not data.startswith(self.MESSAGE):
            raise Exception("Client sent misformed data... Ignoring")

        outgoing = self.INCOMING + b"<From " + sender[0].encode() + b":"
        outgoing += str(sender[1]).encode() + b">: " + data[len(self.MESSAGE):]
        outgoing_sender_hash = sender_hash
        self.handle_outgoing(outgoing, outgoing_sender_hash)

    def handle_outgoing(self, message, sender_hash):
        for peer_hash, peer_address in self.clients.items():
            if peer_hash == sender_hash:
                continue
            self.send_data(message, peer_address)

    def register_greeting(self, peer_hash, peer, data):
        if data.startswith(self.GREETING):
            self.clients[peer_hash] = peer
        else:
            raise Exception("Unexpected message from unregistered peer")

    def handle_incoming(self):
        # block the thread until some message is received
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
        while True:
            try:
                # block until data is received and then add it to the queue
                self.incoming_queue.put(self.recv_data())
            except Exception as e:
                self.handle_exception(e)

def parse_args():
    if not len(sys.argv) == 3:
        print("Invalid program arguments", file=sys.stderr)
        sys.exit(1)

    server = ChatServer(sys.argv[2])
    server.start()
    server.incoming_thread.run()
    server.handle_incoming()

if __name__ == "__main__":
    parse_args()
