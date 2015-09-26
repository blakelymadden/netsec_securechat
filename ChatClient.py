import socket
import sys
import threading

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
        self.incoming_thread = None
        self.input_thread = None

    def print_prompt(self):
        """
        prints the prompt to stdout
        """
        print('+>', end=' ', flush=True)

    def greet_server(self):
        """
        greets the server with the self.GREETING data
        """
        self.send_data(self.GREETING)

    def start(self):
        """
        initializes the client and greets the server
        """
        # initialize the client socket and set up the threads
        # if an OSError is caught, the function iterates self.port and retries
        # creating the socket
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                        socket.IPPROTO_UDP)
            self.socket.bind(('', self.port))

            # set up the threads but do not start them
            self.incoming_thread = threading.Thread(target=self.handle_incoming,
                                                    name="incoming thread")
            self.input_thread = threading.Thread(target=self.handle_input,
                                                 name="input thread")
            # greet the server
            self.greet_server()
        except OSError:
            #handle exceptions raised when the port number is already in use
            self.port += 1
            self.start()

    def handle_exception(self, exception):
        """
        print an exception to the stderr
        """
        print(str(exception), file=sys.stderr)

    def recv_data(self):
        """
        receive data on self.socket
        """
        return self.socket.recv(self.DATA_MAX)

    def send_data(self, data):
        """
        send data to the server
        """
        self.socket.sendto(data, self.server_info)

    def init_session(self):
        """
        initialize the client and start the threads
        """
        self.start()
        self.incoming_thread.start()
        self.input_thread.start()

    def handle_input(self):
        """
        ***BLOCKING***
        read from stdin (blocking) and prompt the user forever.

        this is meant to be used in a dedicated thread to avoid hang ups
        """
        while True:
            self.print_prompt()
            message = self.MESSAGE
            message += sys.stdin.readline(self.DATA_MAX).encode()
            message = message.strip()
            self.send_data(message)

    def handle_incoming(self):
        """
        ***BLOCKING***
        read from self.socket forever send any data received to stdout with
        the "INCOMING" tag removed.

        if an exception is raised from self.recv_data, or when the client
        receives malformed data, print the exception and continue

        this is meant to be used in a dedicated thread to avoid hang ups
        """
        while True:
            try:
                incoming = self.recv_data()
                if not incoming.startswith(self.INCOMING):
                    raise Exception("Invalid data received from server...")
                print('\n<- ' + incoming[len(self.INCOMING):].decode(),
                      flush=True)
                self.print_prompt()
            except Exception as e:
                self.handle_exception(e)

def parse_args_and_start():
    """
    read the CL arguments and use them as parameters for a new ChatClient.
    then start the ChatClient
    """
    if not len(sys.argv) == 5:
        print("Invalid program arguments", file=sys.stderr)
        sys.exit(1)

    client = ChatClient((sys.argv[2], int(sys.argv[4])))
    client.init_session()

# main guard
if __name__ == "__main__":
    parse_args_and_start()
