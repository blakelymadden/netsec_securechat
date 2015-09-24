import select
import socket
import sys

class ChatClient:
    INCOMING = b"INCOMING"
    GREETING = b"GREETING"
    MESSAGE = b"MESSAGE"

    def __init__(self, server_info, port=10002, DATA_MAX=8192):
        """ Initialize a chat client instance
        server_info : a pair of (hostaddr, port) for the remote host
        port : optional argument to specify the port the client will use
                   for outgoing datagrams
        DATA_MAX : optional argument to specify the max packet size for reading
                   incoming datagrams
        """
        self.DATA_MAX = DATA_MAX
    
        self.port = int(port)
        self.server_info = server_info
        self.socket = None
        self.epoll = None
        self.ready_buf = b''

    def print_prompt(self):
        print('+>', end=' ', flush=True)

    def greet_server(self):
        self.send_data(self.GREETING)

    def start(self):
        # initialize the client socket
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                        socket.IPPROTO_UDP)
            #self.socket.setblocking(False)
            self.socket.bind(('', self.port))
            self.epoll = select.epoll()
            self.epoll.register(self.socket, select.EPOLLIN)
            self.epoll.register(sys.stdin, select.EPOLLIN)
            # greet the server
            self.greet_server()
        except OSError:
            self.port += 1
            self.start()

    def recv_data(self):
        return self.socket.recv(self.DATA_MAX)

    def send_data(self, data):
        self.socket.sendto(data, self.server_info)

    def init_session(self):
        self.start()
        self.print_prompt()
        self.read_write_wait()

    def handle_input(self):
        self.ready_buf = self.MESSAGE
        self.ready_buf += sys.stdin.readline(self.DATA_MAX).encode()
        self.ready_buf = self.ready_buf.strip()
        self.print_prompt()
        self.handle_outgoing(self.socket.fileno())

    def handle_outgoing(self, fd):
        if not fd == self.socket.fileno():
            raise Exception("Unexpected fd caught... Ignoring")

        self.send_data(self.ready_buf)
        self.ready_buf = b''

    def handle_incoming(self, fd):
        if not fd == self.socket.fileno():
            raise Exception("Unexpected fd caught... Ignoring")

        incoming = self.recv_data()
        if not incoming.startswith(self.INCOMING):
            raise Exception("Invalid data received from server...")
        print('\n<- ' + incoming[len(self.INCOMING):].decode())
        self.print_prompt()

    def read_write_wait(self):
        if self.epoll is None:
            raise Exception("Client tried to listen before initialization...")

        while True:
            # start polling for incoming messages or user input
            events = self.epoll.poll()
            for fd, event in events:
                try:
                    if event & select.EPOLLIN:
                        if fd == sys.stdin.fileno():
                            self.handle_input()
                        else:
                            self.handle_incoming(fd)
                except Exception as e:
                    print(str(e), file=sys.stderr)

def parse_args():
    if not len(sys.argv) == 5:
        print("Invalid program arguments", file=sys.stderr)
        sys.exit(1)

    client = ChatClient((sys.argv[2], int(sys.argv[4])))
    client.init_session()

if __name__ == "__main__":
    parse_args()
