import select
import socket
import sys

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
        self.epoll = None
        self.outgoing_ready = False
        self.outgoing = ''
        self.outgoing_sender_hash = None

    def start(self):
        # initialize incoming socket and epoll
        self.socket_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                       socket.IPPROTO_UDP)
        self.socket_in.setblocking(False)
        self.socket_in.bind(('', self.port_in))
        self.epoll = select.epoll()
        self.epoll.register(self.socket_in, select.EPOLLIN)

        # initialize outgoing socket
        ############################
        # the same socket will be used for all outgoing datagrams
        self.socket_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                        socket.IPPROTO_UDP)
        self.socket_out.bind(('', self.port_out))
        #self.epoll.register(self.socket_out, select.EPOLLOUT)
        print("Server Initialized")

    def recv_data(self):
        return self.socket_in.recvfrom(self.DATA_MAX)

    def send_data(self, data, address):
        self.socket_out.sendto(data, address)

    def handle_continuation(self, sender_hash, sender, data):
        if not data.startswith(self.MESSAGE):
            raise Exception("Client sent misformed data... Ignoring")

        self.outgoing = self.INCOMING + b"<From " + sender[0].encode() + b":"
        self.outgoing += str(sender[1]).encode() + b">: " + data[len(self.MESSAGE):]
        self.outgoing_sender_hash = sender_hash
        self.outgoing_ready = True
        self.handle_outgoing()

    def handle_outgoing(self):
        if not self.outgoing_ready:
            return

        for peer_hash, peer_address in self.clients.items():
            if peer_hash == self.outgoing_sender_hash:
                continue
            self.send_data(self.outgoing, peer_address)
        self.outgoing_ready = False
        self.outgoing_sender_hash = None

    def receive_greeting_and_register(self, peer_hash, peer, data):
        if data.startswith(self.GREETING):
            self.clients[peer_hash] = peer
        else:
            raise Exception("Unexpected message from unregistered peer")

    def handle_packet(self, fd):
        if not fd == self.socket_in.fileno():
            raise Exception("Unexpected I/O event captured... Ignoring")

        data = self.recv_data()
        peer = data[1]
        peer_hash = hash(peer)
        if self.clients.get(peer_hash) is not None:
            self.handle_continuation(peer_hash, peer, data[0])
        else:
            self.receive_greeting_and_register(peer_hash, peer, data[0])

    def wait_for_message(self):
        if self.epoll is None:
            raise Exception("Server tried to listen before initialization...")

        while True:
            events = self.epoll.poll()
            for fd, event in events:
                try:
                    if event & select.EPOLLIN:
                        self.handle_packet(fd)
                except Exception as e:
                    print(str(e), file=sys.stderr)

def parse_args():
    if not len(sys.argv) == 3:
        print("Invalid program arguments", file=sys.stderr)
        sys.exit(1)

    server = ChatServer(sys.argv[2])
    server.start()
    server.wait_for_message()

if __name__ == "__main__":
    parse_args()
