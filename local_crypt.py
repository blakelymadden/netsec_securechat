# -*- coding: utf-8 -*-
import sys, os, hashlib, random
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padd2
from cryptography.exceptions import InvalidSignature, InvalidKey
import l_globals as LG

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

AES_KEY_SIZE = 32
################################

# a one-way hash function
def H(*a):  
    a = ':'.join([str(a) for a in a])
    return int(hashlib.sha256(a.encode('ascii')).hexdigest(), 16)

## pads the given data to be of length n
#def padd(data, n=LG.PADD_BLOCK * 8):
#    #data = bytes(data.encode('utf-8'))
#    padder = padd2.PKCS7(n).padder()
#    padded_data = padder.update(data)
#    padded_data += padder.finalize()
#    return padded_data

## unpads the given data from n bytes
#def unpadd(padded_data, n=LG.PADD_BLOCK * 8):
#    #padded_data = bytes(padded_data.encode('utf-8'))
#    unpadder = padd2.PKCS7(n).unpadder()
#    data = unpadder.update(padded_data)
#    data += unpadder.finalize()
#    return data

# generates a random crypto string 
def cryptrand(n=1024):
    return random.SystemRandom().getrandbits(n) % N

# creates a 16 bit cryptographic salt
def gen_salt(size=16):
    return os.urandom(size)
    
# Generates public key from private key and saves it at dest
def gen_pub_key(dest, priv_key_f):
    with open(priv_key_f, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    public_key = private_key.public_key()
    
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(dest, 'wb') as dest_f:
        dest_f.write(pem)
    
    return
    
    
# Generates private key and saves it at dest
def gen_priv_key(dest, size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend()
    )
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    dest_f = open(dest, 'wb')
    dest_f.write(pem)
    dest_f.close()
    return

# loads the public key at the path given
def load_public_key(path):
    public_key = None
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
    return public_key

############### SRP ################
    
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
        self.password = H(password, uname, N)
        self.a = cryptrand()
        self.M = None
        super(SRP_User, self).__init__(uname)
    
    # creates an initial authentication to send to server
    def start_authentication(self):
        self.A = bytes(str(pow(g, self.a, N)).encode("utf-8"))
        return (self.uname, self.A)
    
    
    def create_session_key(self):
        u = self.gen_rand_scrambler()
        x = H(self.salt, self.uname, self.password)
        S_c = pow(int(self.B) - self.k * pow(g, x, N), self.a + u * x, N)
        K_c = H(S_c)
        self.session_key = str(K_c).encode()[:AES_KEY_SIZE]

    def process_challenge(self, salt, B):
        self.B = B
        self.salt = salt
        self.create_session_key()
        self.M = str(H(H(N) ^ H(g), H(self.uname), self.salt, self.A, self.B, self.session_key)).encode("utf-8")
        return self.M
    
    def verify_session(self, HAMK):
        M_s = str(H(self.A, self.M, self.session_key)).encode("utf-8")
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
        self.B = str((self.k * self.v + pow(g, self.b, N)) % N).encode("utf-8")
        return (self.salt, self.B)
    
    # generates a shared session key
    def create_session_key(self):
        u = self.gen_rand_scrambler()
        S_s = pow(int(self.A) * pow(self.v, u, N), self.b, N)
        K_s = H(S_s)
        self.session_key = str(K_s).encode()[:AES_KEY_SIZE]

    # verifies the users session
    def verify_session(self, M):
        HAMK = None 
        self.create_session_key()
        M_c = str(H(H(N) ^ H(g), H(self.uname), self.salt, self.A, self.B, self.session_key)).encode("utf-8")
        if M_c == M:
            self.is_auth = True
            HAMK = H(self.A, M_c, self.session_key)
            return str(HAMK).encode("utf-8")
        else:
            return None

#################################### 

class AuthenticationFailed (Exception):
    pass


######## Symetric Encryption ########
HMAC_BLOCK = 32
ENDDELIM = "~!~!~"
def sym_enc(data, key, salt):
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
    encryptor = cipher.encryptor()
    #    padder = padd2.PKCS7(LG.PADD_BLOCK).padder()
    #    padded_data = padder.update(data)
    #    padded_data += padder.finalize()
    block_size_bytes = algorithms.AES.block_size / 8
    missing_bytes = block_size_bytes -\
                    ((len(data)
                      + len(self.ENDDELIM)) %
                     block_size_bytes)
    data += self.ENDDELIM
    if missing_bytes: data += os.urandom(missing_bytes)

    ct = encryptor.update(data) + encryptor.finalize()
    return ct

def sym_dec(data, key, salt):
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
    decryptor = cipher.decryptor()
    pad_plain_text = decryptor.update(cipher_text) + decryptor.finalize()
    #unpadder = padd2.PKCS7(LG.PADD_BLOCK).unpadder()
    #plain_text = unpadder.update(pad_plain_text)
    return pad_plain_text.split(ENDDELIM)[0]
    
    
def apply_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    sig = h.finalize()
    return sig + data

def verify_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(key)
    sig = h.finalize()
    data_sig = data[:HMAC_BLOCK]
    return sig == data_sig
    
def enc_and_hmac(data, key, salt):
    ct = sym_enc(data, key, salt)
    return apply_hmac(ct, key)
    
def dec_and_hmac(data, key, salt):
    if verify_hmac(data, key):
        msg = data[HMAC_BLOCK:]
        return sym_dec(msg, key, salt)
    else:
        return None
