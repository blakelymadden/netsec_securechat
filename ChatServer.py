# -*- coding: utf-8 -*-
import queue
import socket
import sys
import threading
import argparse
import signal
import traceback
from datetime import timedelta, datetime
import local_crypt as LC
import l_globals as LG
from l_globals import ERROR, LIST, SEND
from user import User

class ChatServer:
    GREETING = b"GREETING"
    MESSAGE = b"MESSAGE"
    INCOMING = b"INCOMING"
    ATTEMPTS_ALLOWED = 10
    UNLOCK_USER_AFTER = timedelta(minutes=5)
    DELIM = b"~~~~~"
    
    def __init__(self, port_in, port_out=10001, server_ip='', dmax=8192):
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
        self.server_ip = server_ip
        self.clients = {}
        self.logged_in_clients = {}
        self.locked_users = {}
        self.unlock_users_thread = None
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
            self.socket_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_in.bind((self.server_ip, self.port_in))
            # initialize outgoing socket
            ############################
            # the same socket will be used for all outgoing datagrams
            #self.socket_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
            #                                socket.IPPROTO_TCP)
            #self.socket_out.bind((self.server_ip, self.port_out))
            
            # set up the incoming thread and associated data structures
            self.incoming_queue = queue.Queue()
            self.incoming_thread = threading.Thread(target=self.wait_for_message,
                                                    name="incoming_thread")
            #self.unlock_users_thread = threading.Thread(target=self.unlock_users,
            #                                        name="unlock_users_thread")
        except OSError as err:
            self.handle_exception(err)
            exit(0)
            self.port_in = self.port_in - 1
            self.start()

        print("Server Initialized")

    def recv_data(self):
        """
        receive data on self.socket_in
        """
        return self.socket_out.recv(self.DATA_MAX)

    def send_data(self, data):
        """
        send data from self.socket_out
        """
        self.socket_out.sendall(bytes(data))

    def handle_exception(self, exception):
        """
        print an exception to the stderr
        """
        print(str(exception), file=sys.stderr)

    def handle_continuation(self, peer_hash, data):
        """
        handler for data starting with self.MESSAGE

        sets up the outgoing message for the clients to receive and then
        delegates it to self.handle_outgoing
        """
        usr = self.clients.get(peer_hash)[1]
        data = LC.dec_and_hmac(data, usr.verifier.session_key, usr.verifier.salt)
        enc = lambda s: LC.enc_and_hmac(s, usr.verifier.session_key, usr.verifier.salt)
        if data is None:
            self.send_data("Failed to authenticate message")
            raise Exception("Failed to authenticate")
        if data == LIST:
            u_list = "\n".join(self.logged_in_clients)
            s_data = enc(u_list)
            self.send_data(s_data)
        elif data.startswith(SEND):
            uname = data[len(SEND) + 1 :]
            usr = self.logged_in_clients.get(uname)
            if usr is not None:
                s_data = bytes("{0}:{1}".format(usr.address, user.port_in)) + self.DELIM + enc(usr.pub_key)
                self.send_data(s_data)
            else: 
                s_data = enc(self.ERROR + b": User is not logged in")
                self.send_data(s_data)
                raise Exception("User is not logged in")
                

#    def handle_outgoing(self, message, sender_hash):
#        """
#        send a message to everyone in self.clients except for item matching
#        sender_hash
#        """
#        for peer_hash, peer_address in self.clients.items():
#            if peer_hash == sender_hash:
#                continue
#            self.send_data(message)
#

    def handle_login_init(self, peer_hash, peer, content):
        """
        logs in a client using srp
        """
        #p_uname = bytes(content[:LG.PADD_BLOCK])
        #uname = LC.unpadd(p_uname).decode("utf-8")
        uname = content.split(self.DELIM)[0].decode()
        self.handle_login_user(uname, peer)
        print(uname)
        usr = User.load_user_from_json(uname)
        if usr is None:
            self.send_data(b"No such user!")
            raise Exception("No such user!")
        self.handle_locked_user(usr, peer)
        usr.attempt()
        #A = int(content[LG.PADD_BLOCK:])
        A = int(content.split(self.DELIM)[1])
        usr.verifier = LC.SRP_Verifier(uname, LC.gen_salt(), usr.pw, A)
        s, B = usr.verifier.get_challenge()
        #response = LC.padd(bytes(s)) + bytes(B)
        response = bytes(s) + self.DELIM + bytes(B)
        self.send_data(bytes(response))
        self.clients[peer_hash] = (peer, usr)
    
    def handle_user_verification(self, peer_hash, peer, content):
        usr = self.clients.get(peer_hash)[1]
        if usr is None:
            self.handle_login_init(peer, content)
        else:
            self.handle_login_user(usr.name, peer)
            self.handle_locked_user(usr, peer)
            HAMK = usr.verifier.verify_session(content)
            self.send_data(bytes(HAMK))
            if not usr.verifier.authenticated():
                self.clients[peer_hash][1] = None
                raise LC.AuthenticationFailed()
            else:
                self.logged_in_clients[usr.name] = usr
                
    def handle_login_user(self, uname, peer):
        time = self.locked_users.get(uname)
        if time is not None and datetime.now() - time >= UNLOCK_USER_AFTER:
            self.locked_users.pop(uname)
        if uname in list(self.logged_in_clients.keys()):
            self.send_data(ERROR + b": User is logged in already")
            raise Exception(ERROR + b": User is logged in already")
    
    def handle_locked_user(self, usr, peer):
        msg = ERROR + b": User has been locked"
        if usr.name in list(self.locked_users.keys()):
            self.send_data(msg)
            raise Exception(msg)
        usr.attempt()
        if usr.attempts > self.ATTEMPTS_ALLOWED:
            self.locked_users[usr.name] = datetime.now()
            self.send_data(msg)
            raise Exception(msg)            
    
#    def unlock_users(self):
#        """
#        checks if a user is ready to be unlocked and removes them
#        from the locked list if they are
#        """
#        for (uname, time) in self.locked_users:
#            if datetime.now() - time >= UNLOCK_USER_AFTER:
#                self.locked_users.pop(uname)
            
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
                self.socket_out = data[0]
                peer = data[1]
                peer_hash = hash(peer)
                content = self.recv_data()
                peer_pair = self.clients.get(peer_hash)
                if peer_pair is not None:
                    if not peer_pair[1].verifier.authenticated():
                        self.handle_user_verification(peer_hash, peer, content)
                    else:
                        self.handle_continuation(peer_hash, peer, content)
                else:
                    self.handle_login_init(peer_hash, peer, content)
            except Exception as e:
                traceback.print_exc()
                self.handle_exception(e)

    def wait_for_message(self):
        """
        ***BLOCKING***
        wait to receive data and then add it to self.incoming_queue for
        processing.

        this is meant to be used in a dedicated thread to avoid hang ups.
        """
        self.socket_in.listen(1)

        while True:
            try:
                # block until data is received and then add it to the queue
                sock, info = self.socket_in.accept()
                self.incoming_queue.put((sock, info))
            except Exception as e:
                self.handle_exception(e)
                
#msudo-graceful sigint handler
def signal_handler(signal, frame):
    print('\nServer Shut Down', flush=True)
    serv_socket.close()
    sys.exit()

def parse_args():
    """
    read the CL arguments and use them as parameters for a new ChatServer.
    then start the ChatServer
    """
    if not len(sys.argv) == 3:
        print("Invalid program arguments", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', '--server_port', help='the host\'s server open port number', required=True)
    args = parser.parse_args()
        
    server = ChatServer(args.server_port)
    server.start()
    server.incoming_thread.start()
    #server.unlock_users_thread.start()

    # no reason to spawn an additional thread since the main thread isn't
    # doing anything anyway
    server.handle_incoming()

# main guard
if __name__ == "__main__":
    #sigint handler
    #signal.signal(signal.SIGINT, signal_handler)
    parse_args()
