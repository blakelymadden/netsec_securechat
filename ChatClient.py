import socket
import sys
import threading
import traceback
import local_crypt as LC
import l_globals as LG
from l_globals import LIST, SEND
from cryptography.hazmat.backends import openssl, default_backend
from cryptography.hazmat.primitives import hashes, serialization, asymmetric, ciphers
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
import os

enc = lambda s: LC.enc_and_hmac(s, usr.verifier.session_key, usr.verifier.salt)

class ChatClient:
    INCOMING = b"INCOMING"
    GREETING = b"GREETING"
    MESSAGE = b"MESSAGE"
    SEND = b"send "
    LIST = b"list"
    DELIM = b"~~~~~"
    ENDDELIM = b"~!~!~"
    
    def __init__(self, server_info, privkey, port=10002, DATA_MAX=8192):
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
        self.socket_wait = None
        self.socket_out = None
        self.incoming_thread = None
        self.input_thread = None
        self.peer = None
        self.session_key = None
        self.salt = None
        self.peers = {}
        self.active_sessions = {}
        self.backend = openssl.backend
        self.privkey = None
        self.name = None
        with open(privkey, 'rb') as privkey_f:
            self.privkey = serialization.load_pem_private_key(privkey_f.read(),
                                                              password=None,
                                                              backend=self.backend)

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
        uname = sys.stdin.readline(self.DATA_MAX)
        uname = uname.strip()
        self.name = uname
        print("Enter Password")
        self.print_prompt()
        password = sys.stdin.readline(self.DATA_MAX)
        password = password.strip()
        srp_usr = LC.SRP_User(uname, password)
        uname, A = srp_usr.start_authentication()
        #p_uname = LC.padd(uname)
        message = uname.encode() + self.DELIM + A
        self.send_data(message)
        incoming = self.recv_data()
        salt = None
        while(len(incoming) == 0):
            incoming = self.recv_data()
        if len(incoming.split(self.DELIM)) <= 1:
            print(str(incoming))
            self.greet_with_srp()
        try: 
            salt = incoming.split(self.DELIM)[0]
            #salt = LC.unpadd(bytes(incoming[:LG.PADD_BLOCK]))
        except ValueError as ve:
            try:
                print(str(incoming).decode("uf8-8"))
            except Exception as e:
                self.handle_exception(ve)
                self.handle_exception(e)
            return False
        self.salt = salt
        B = incoming.split(self.DELIM)[1]
#        print(b"B: " + B)
        #B = incoming[LG.PADD_BLOCK:]
        M = srp_usr.process_challenge(salt, B)
#        print(b"M: " + M)
        if M is None:
            print("\nFailed to Authenticate user:" + uname)
            exit(1)
        self.send_data(M)
        incoming = ""
        while(len(incoming) == 0):
            incoming = self.recv_data()
        srp_usr.verify_session(incoming)
        if srp_usr.authenticated():
            self.session_key = srp_usr.session_key
            print("\nSuccessfully Logged In")
            self.print_prompt()
        else:
            print("\nFailed to Authenticate user:" + uname.decode("utf-8"))
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
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect(self.server_info)
            #self.socket.bind(('', self.port))

            self.socket_wait = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_wait.bind(('', self.port))
            self.socket_wait.listen(1)

            self.socket_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                            socket.IPPROTO_UDP)
            print(self.socket.getsockname())
            self.socket_out.bind(self.socket.getsockname())

            # greet the server
            logged = False
            while not logged: logged = self.greet_with_srp()
            
            # set up the threads but do not start them
            self.incoming_thread = threading.Thread(target=self.handle_incoming,
                                                    name="incoming thread")
            self.input_thread = threading.Thread(target=self.handle_input,
                                                 name="input thread")
        except OSError as e:
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

    def send_data(self, data, crypt=False):
        """
        send data to the server
        """
        if crypt:
            enc = lambda s: LC.enc_and_hmac(s, self.session_key, self.salt)
            data = enc(data)
        self.socket.sendall(data)

    def init_session(self):
        """
        initialize the client and start the threads
        """
        self.start()
        self.incoming_thread.start()
        self.input_thread.start()

    def server_query(self, message):
        dec = lambda s: LC.dec_and_hmac(s, self.session_key, self.salt)
        if message == LIST:
            self.send_data(message, True)
            response = dec(self.recv_data())
            print(response)
            self.print_prompt()
        elif message[:len(SEND)] == SEND:
            self.send_data(message, True)
            response = dec(self.recv_data())
            split1 = response.split(b':')
            split2 = split1[1].split(self.DELIM)
            key = serialization.load_pem_public_key(split2[1], backend=default_backend())
            self.peers[message.split(b' ',2)[1]] = [(split1[0], split2[0], key)]
            self.peer_session(message)

    def aes_encrypt(self, message, peer_key, peer_iv):
        # set up the plaintext (padded if needed) for AES encryption
        plaintext = message
        block_size_bytes = int(ciphers.algorithms.AES.block_size / 8)
        missing_bytes = block_size_bytes -\
                        ((len(plaintext)
                          + len(self.ENDDELIM)) %
                         block_size_bytes)
        plaintext += self.ENDDELIM
        if missing_bytes: plaintext += os.urandom(int(missing_bytes))
        
        # split the plaintext into blocks for the AES CBC algorithm to use
        blocks = []
        for i in range(0, int(len(plaintext) / block_size_bytes)):
            blocks.append(
                plaintext[i*block_size_bytes:(i+1)*block_size_bytes])
            
        # set up the AES encryptor with the key and iv
        encryptor = ciphers.Cipher(
            ciphers.algorithms.AES(peer_key),
            ciphers.modes.CBC(peer_iv),
            self.backend
        ).encryptor()
        
        # encrypt all of the message blocks
        encrypted_blocks = []
        for block in blocks:
            encrypted_blocks.append(encryptor.update(block))
        blocks.append(encryptor.finalize())

        out = b''
        # write the AES encrypted message to the output file
        for block in encrypted_blocks:
            out+= block
        return out

    def aes_decrypt(self, message, peer_info):
        # set up the decryptor using the aes 256 key and iv
        decryptor = ciphers.Cipher(
            ciphers.algorithms.AES(peer_info[1][0]),
            ciphers.modes.CBC(peer_info[1][1]),
            self.backend
        ).decryptor()
        # decrypt the AES ciphertext and split it into the message and
        # signature
        plaintext = decryptor.update(message) + decryptor.finalize()
        return plaintext.split(self.ENDDELIM)[0]

    def init_peer_session(self, message, peer_info):
        peer_host_port = (peer_info[0][0], int(peer_info[0][1]))
        peer_pub = peer_info[0][2]

        # generate the random key and initialization vector for aes256
        aeskey = os.urandom(32)
        aesiv = os.urandom(16)

        peer_info.append((aeskey, aesiv))

        rsa_data = aesiv + self.DELIM + aeskey

        enc_aes_key_iv = peer_pub.encrypt(
            rsa_data, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None))

        rsa_signer = self.privkey.signer(
            asymmetric.padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH)
            ,hashes.SHA256())

        rsa_signer.update(rsa_data)
        rsa_sig = rsa_signer.finalize()

        self.socket_out.sendto(enc_aes_key_iv + self.DELIM + rsa_sig, peer_host_port)
        received = None
        #while True:
        #    received = self.socket_out.recvfrom(DATA_MAX)
        #    if not received[1] == peer_addr:
        #        continue
        self.peer_session(message)

    def peer_session(self, message):
        peer_split = message.split(b' ', 2)
        peer_info = self.peers.get(peer_split[1])

        try:
            self.peers.get(peer_split[1])[1]
        except:
            self.init_peer_session(message, peer_info)

        tosend = self.name.encode() + self.DELIM \
            + self.aes_encrypt(peer_split[2], peer_info[1][0], peer_info[1][1])
        print(peer_info)
        self.socket_out.sendto(tosend, (peer_info[0][0], int(peer_info[0][1])))

    def handle_input(self):
        """
        ***BLOCKING***
        read from stdin (blocking) and prompt the user forever.

        this is meant to be used in a dedicated thread to avoid hang ups
        """
        while True:
            try:
                self.print_prompt()
                message = sys.stdin.readline(self.DATA_MAX).encode().strip()
                if message == LIST or message[:len(SEND)] == SEND:
                    self.server_query(message)
                else:
                    self.peer_session(message)
            except Exception as e:
                print(e)
                traceback.print_exc()
                print("Error receiving user input")
                
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
                incoming = self.socket_out.recv(self.DATA_MAX)
                incoming_l = incoming.split(self.DELIM, 1)
                peer_info = self.peers.get(incoming_l[0])
                print(incoming_l[0] + b'\n' + incoming_l[1])
                print('\n<- ' + self.aes_decrypt(incoming_l[1], peer_info), flush=True)
                self.print_prompt()
            except Exception as e:
                self.handle_exception(e)

def parse_args_and_start():
    """
    read the CL arguments and use them as parameters for a new ChatClient.
    then start the ChatClient
    """
    if not len(sys.argv) == 7:
        print("Invalid program arguments", file=sys.stderr)
        sys.exit(1)

    client = ChatClient((sys.argv[2], int(sys.argv[4])), privkey=sys.argv[6])
    client.init_session()

# main guard
if __name__ == "__main__":
    parse_args_and_start()
