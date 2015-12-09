# -*- coding: utf-8 -*-
import hashlib, random

###### Crypto Globals ######

# A large safe prime (N = 2q+1, where q is prime)
# All arithmetic is done modulo N
# (generated using "openssl dhparam -text 1024")
N = '''00:b2:4f:1d:45:da:b5:f8:d2:c7:6b:a7:f5:ed:0a:
    0c:a9:29:1a:2c:9e:bd:dd:2a:b5:74:9d:76:20:5a:
    e0:a2:98:ea:9b:80:51:8a:f0:8d:bb:1a:55:67:a4:
    c3:39:d4:a0:27:19:6b:ed:56:4b:a6:9b:4f:94:9c:
    2d:99:4f:99:be:42:9f:50:91:4a:15:33:57:d3:c6:
    36:b0:e1:94:c1:f4:a9:6b:f3:d9:81:4c:f6:9b:ea:
    17:89:4e:56:fa:dc:e8:40:a6:9b:8f:f1:ad:34:69:
    87:e0:27:ed:25:4f:16:e2:68:e8:e8:82:e0:37:35:
    61:fd:bc:af:7a:31:98:80:bb'''
N = int(''.join(N.split()).replace(':', ''), 16)

g = 2

################################

# a one-way hash function
def H(*a):  
    a = ':'.join([str(a) for a in a])
    return int(hashlib.sha256(a.encode('ascii')).hexdigest(), 16)


# generates a random crypto string 
def cryptrand(n=1024):
    return random.SystemRandom().getrandbits(n) % N

# creates a 16 bit cryptographic salt
def gen_salt(size=16):
    return cryptrand(size)
    
# SRP super class    
class SRP(object):
    def __init__(self, uname):
        self.uname = uname
        self.is_auth = False
        self.A = None
        self.B = None
        self.session_key = None
        # Multiplier parameter
        self.k = H(N, g)
        self.salt = None
        
    # generates a random scrambling parameter using A and B
    def gen_rand_scrambler(self):
        if self.A is None or self.B is None:
            return None
        return H(self.A, self.B)  # Random scrambling parameter
        
    def authenticated(self):
        return self.is_auth
    
    
# SRP User class
class SRP_User(SRP):

    def __init__(self, uname, password):
        self.password = password
        self.a = cryptrand()
        self.M = None
        super(SRP_User, self).__init__(uname)
    
    # creates an initial authentication to send to server
    def start_authentication(self):
        self.A = pow(g, self.a, N)
        return (self.uname, self.A)
    
    
    def create_session_key(self):
        u = self.gen_rand_scrambler()
        x = H(self.salt, self.uname, self.password)
        S_c = pow(self.B - self.k * pow(g, x, N), self.a + u * x, N)
        K_c = H(S_c)
        self.session_key = K_c

    def process_challenge(self, salt, B):
        self.B = B
        self.salt = salt
        self.create_session_key()
        self.M = H(H(N) ^ H(g), H(self.uname), self.salt, self.A, self.B, self.session_key)
        return self.M
    
    def verify_session(self, HAMK):
        M_s = H(A, self.M, self.session_key)
        if M_s == HAMK:
            self.is_auth = True 
    
# SRP Verifier class
class SRP_Verifier(SRP):
    
    def __init__(self, uname, salt, password, A):
        self.x = H(salt, uname, password)       # Private key
        self.v = pow(g, self.x, N)              # Password verifier
        self.b = cryptrand()
        super(SRP_Verifier, self).__init__(uname)
        self.A = A
        self.salt = salt
        
    # gets the inital challenge that the server will send
    def get_challenge(self):
        self.B = (self.k * self.v + pow(g, self.b, N)) % N
        return (salt, self.B)
    
    # generates a shared session key
    def create_session_key(self):
        u = self.gen_rand_scrambler()
        S_s = pow(self.A * pow(self.v, u, N), self.b, N)
        K_s = H(S_s)
        self.session_key = K_s

    # verifies the users session
    def verify_session(self, M):
        HAMK = None 
        self.create_session_key()
        M_c = H(H(N) ^ H(g), H(self.uname), self.salt, self.A, self.B, self.session_key)
        if M_c == M:
            self.is_auth = True
            HAMK = H(A, M_c, self.session_key)
            return HAMK
        else:
            return None
        
class AuthenticationFailed (Exception):
    pass
