import socket
import sys
import threading
import local_crypt as LC
import l_globals as LG

#enc = lambda s: LC.enc_and_hmac(s, usr.verifier.session_key, usr.verifier.salt)

class ChatClient:
    INCOMING = b"INCOMING"
    GREETING = b"GREETING"
    MESSAGE = b"MESSAGE"
    SEND = b"send "
    LIST = b"list"
    
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
        self.session_key = None
        self.salt = None
        self.user_keys = {}

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

    def greet_with_srp(self):
        """
        authenticates the user with the server using srp
        """
        print("Enter Username")
        self.print_prompt()
        uname = sys.stdin.readline(self.DATA_MAX).encode()
        uname = uname[:len(uname) - 1]
        print("Enter Password")
        self.print_prompt()
        password = sys.stdin.readline(self.DATA_MAX).encode()
        password = password[:len(password) - 1]
        srp_usr = LC.SRP_User(uname, password)
        uname, A = srp_usr.start_authentication()
        p_uname = LC.padd(uname)
        message = p_uname + A
        self.send_data(message)
        incoming = self.recv_data()
        salt = None
        while(len(incoming) == 0):
            incoming = self.recv_data()
        try: 
            salt = LC.unpadd(bytes(incoming[:LG.PADD_BLOCK]))
        except ValueError as ve:
            try:
                print(str(incoming).decode("uf8-8"))
            except Exception as e:
                self.handle_exception(ve)
                self.handle_exception(e)
            return False
        self.salt = salt
        B = incoming[LG.PADD_BLOCK:]
        M = srp_usr.process_challenge(salt, B)
        if M is None:
            print("\nFailed to Authenticate user:" + uname)
            exit(1)
        self.send_data(M)
        while(len(incoming) == 0):
            incoming = self.recv_data()
        srp_usr.verify_session(incoming)
        if srp_usr.authenticated():
            self.session_key = srp_usr.session_key
            print("\nSuccessfully Logged In")
            self.print_prompt()
        else:
            print("\nFailed to Authenticate user:" + uname)
            exit(1)
        return True

    def start(self):
        """
        initializes the client and greets the server
        """
        # initialize the client socket and set up the threads
        # if an OSError is caught, the function iterates self.port and retries
        # creating the socket
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                                        socket.IPPROTO_TCP)
            self.socket.connect(self.server_info)
            #self.socket.bind(('', self.port))

            # greet the server
            while True:
                logged = self.greet_with_srp()
                if logged:
                    break
            
            # set up the threads but do not start them
            self.incoming_thread = threading.Thread(target=self.handle_incoming,
                                                    name="incoming thread")
            self.input_thread = threading.Thread(target=self.handle_input,
                                                 name="input thread")
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

    def send_data(self, data, crypt=None, *args):
        """
        send data to the server
        """
        if crypt is not None:
            data = crypt(data, args)
        self.socket.sendall(data)

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
            try:
                
                print("todo")
#                self.print_prompt()
#                message = sys.stdin.readline(self.DATA_MAX).encode()
#                if message == LIST:
#                    message = message.strip()
#                    self.send_data(message, crypt=True)
#                elif message.startswith(SEND):
#                    ### BLAKE YOU DO THIS PART ###
#                    uname = data[len(send) + 1 :]
#                    if uname in list(self.user_keys.keys()):
#                        print("u got this blake")
#                    else:
#                        data = LC.enc_and_hmac(message, self.session_key, self.salt)
#                        self.send_data(data, crypt=True)
#                        incoming = None
#                        while(len(incoming) == 0):
#                            incoming = self.recv_data()
#                        if incoming is not None:
#                            incoming = LC.enc_and_hmac(incoming, self.session_key, self.salt)
#                            self.user_keys[uname] = incoming
#                            #### BLAKE! ###
#                            print("u got this blake")
                        
            except:
                print("udp exception")
                
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
