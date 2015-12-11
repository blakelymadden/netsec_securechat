from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives import hashes, serialization, asymmetric, ciphers
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
import os
import sys

class fcrypt_base(object):
    """
    base class for the fencryptor and fdecryptor classes

    contains static data for use throughout the program. Some static data
    is for future use.

    also contains functionality shared between the two subclasses
    """
    PEM_RE = r"-----BEGIN.*?-----[\s\S]*?-----END.*?-----"
    SEPARATION_DELIM = b"\n~~~~~\n"
    SHA_256 = hashes.SHA256
    SHA_512 = hashes.SHA512
    MD5 = hashes.MD5
    AES_256 = algorithms.AES

    def __init__(self, pubkey_file, privkey_file, input_file, output_file,
                 hash_func=SHA_256):
        """
        pubkey_file: the public key to be used. This key is either the sender's
                     or the receiver's depending on whether encryption or
                     decryption is being done.
        privkey_file: the private key to be used. Same rule as pubkey_file
                      applies
        input_file: either the plaintext or the ciphertext depending on
                    decryption or encryption
        output_file: the output (ciphertext or plaintext depending on decryption
                     or encryption
        hash_func: optional argument to choose the hash function used in RSA
                   signing. Defaults to SHA256
        """
        self.hash_func = hash_func
        self.output_f = output_file
        self.input_f = input_file
        self.backend = openssl.backend
        self.privkey = None
        self.pubkey = None
        self.get_keys(privkey_file, pubkey_file)

    def handle_exception(self, e, crash=False):
        """Prints an exception with optional program termination"""
        print str(e)
        if crash: sys.exit(1)
        
    def metadata(self, delim=SEPARATION_DELIM):
        """Returns the metadata for the output file"""
        return b"HASHf:" + self.hash_func.name + delim

    def get_keys(self, privkey_f, pubkey_f):
        """
        extracts public and private keys from the corresponding files that
        this object was created with
        """
        with open(pubkey_f, "rb") as pubkey_file\
             ,open(privkey_f, "rb") as privkey_file:
            # read in the serialized public key
            pubkey_serialized = pubkey_file.read()
            # deserialize the recipient's public key from PEM
            self.pubkey = serialization.load_pem_public_key(
                pubkey_serialized, backend=self.backend)
            # read in the serialized private key
            privkey_serialized = privkey_file.read()
            # deserialize the sender's private key from PEM 
            self.privkey = serialization.load_pem_private_key(
                privkey_serialized, password=None, backend=self.backend)

class fencrypt(fcrypt_base):
    """
    class for encrypting a message
    """
    def __init__(self, pubkey_file, privkey_file, input_file, output_file):
        """see fcrypt_base"""
        super(fencrypt, self).__init__(pubkey_file, privkey_file,
                                       input_file, output_file)

    def encrypt(self):
        """
        encrypt plaintext and output ciphertext
        """
        with open(self.input_f, "rb") as plaintext_file\
             ,open(self.output_f, "wb") as output_file:
            # generate the random key and initialization vector for aes256
            aeskey = os.urandom(32)
            aesiv = os.urandom(16)

            # write the metadata to the output file
            output_file.write(super(fencrypt,self).metadata())

            rsa_data = aesiv + fcrypt_base.SEPARATION_DELIM + aeskey
            # encrypt the aes256 shared key and initialization vector using the
            # provided RSA public key and write the encrypted data to the output
            # file
            output_file.write(self.pubkey.encrypt(
                rsa_data, padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None)))

            # write a delimiter to separate the key info from the message
            output_file.write(fcrypt_base.SEPARATION_DELIM)

            # sign the aesiv+delimiter+aeskey using the RSA private key
            rsa_signer = self.privkey.signer(
                asymmetric.padding.PSS(
                    mgf=padding.MGF1(self.hash_func()),
                    salt_length=padding.PSS.MAX_LENGTH)
                ,self.hash_func())
            rsa_signer.update(rsa_data)
            rsa_sig = rsa_signer.finalize()

            # set up the plaintext (padded if needed) for AES encryption
            plaintext = plaintext_file.read() + fcrypt_base.SEPARATION_DELIM\
                        + rsa_sig
            block_size_bytes = ciphers.algorithms.AES.block_size / 8
            missing_bytes = block_size_bytes -\
                            ((len(plaintext)
                              + len(fcrypt_base.SEPARATION_DELIM)) %
                             block_size_bytes)
            plaintext += fcrypt_base.SEPARATION_DELIM
            if missing_bytes: plaintext += os.urandom(missing_bytes)
            
            # split the plaintext into blocks for the AES CBC algorithm to use
            blocks = []
            for i in range(0, len(plaintext) / block_size_bytes):
                blocks.append(
                    plaintext[i*block_size_bytes:(i+1)*block_size_bytes])

            # set up the AES encryptor with the key and iv
            encryptor = ciphers.Cipher(
                ciphers.algorithms.AES(aeskey),
                ciphers.modes.CBC(aesiv),
                self.backend
            ).encryptor()

            # encrypt all of the mesage blocks
            encrypted_blocks = []
            for block in blocks:
                encrypted_blocks.append(encryptor.update(block))
            blocks.append(encryptor.finalize())

            # write the AES encrypted message to the output file
            for block in encrypted_blocks:
                output_file.write(block)

class fdecrypt(fcrypt_base):
    """
    class for decrypting a message
    """
    def __init__(self, pubkey_file, privkey_file, input_file, output_file):
        """see fcrypt_base"""
        super(fdecrypt, self).__init__(pubkey_file, privkey_file,
                                       input_file, output_file)

    def decrypt(self):
        """decrypt the ciphertext and output plaintext"""
        with open(self.input_f, "rb") as ciphertext_file\
             ,open(self.output_f, "wb") as output_file:

            ciphertext = ciphertext_file.read()
            meta = rsa_encrypted = aes_encrypted = None
            # split the ciphertext into the three fields or raise an exception
            # if not exactly 3 fields are present
            try:
                meta, rsa_encrypted, aes_encrypted = ciphertext.split(
                    fcrypt_base.SEPARATION_DELIM)
            except:
                raise Exception("Unreadable ciphertext file")
            # decrypt the RSA field and extract the aes 256 key and iv
            aesiv,aeskey = self.privkey.decrypt(rsa_encrypted, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None)).split(fcrypt_base.SEPARATION_DELIM)
            # set up the decryptor using the aes 256 key and iv
            decryptor = ciphers.Cipher(
                ciphers.algorithms.AES(aeskey),
                ciphers.modes.CBC(aesiv),
                self.backend
            ).decryptor()
            # decrypt the AES ciphertext and split it into the message and
            # signature
            plaintext = decryptor.update(aes_encrypted) + decryptor.finalize()
            message, rsa_sig, _ = plaintext.split(fcrypt_base.SEPARATION_DELIM)
            # set up the verifier and verify the signature found in the
            # ciphertext
            rsa_verifier = self.pubkey.verifier(
                rsa_sig,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_func()),
                    salt_length=padding.PSS.MAX_LENGTH),
                self.hash_func())
            rsa_verifier.update(aesiv + fcrypt_base.SEPARATION_DELIM + aeskey)
            rsa_verifier.verify()
            # finally, output the original message
            output_file.write(message)

def setup_encrypt():
    """function to handle command line args for encryption"""
    encryptor = fencrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    encryptor.encrypt()

def setup_decrypt():
    """function to handle command line args for decryption"""
    decryptor = fdecrypt(sys.argv[3], sys.argv[2], sys.argv[4], sys.argv[5])
    decryptor.decrypt()

def parse_args():
    """print a usage message when called with the wrong # of args.
    delegates further responsibility to setup_* functions"""
    if not len(sys.argv) == 6:
        usage = "usage: -e destination_public_key_filename sender_private_key"
        usage += "_filename input_plaintext_file ciphertext_file\nusage: -d "
        usage += "destination_private_key_filename sender_public_key_filename "
        usage += "ciphertext_file output_plaintext_file"
        print(usage)
        sys.exit(1)
    if sys.argv[1] == '-e':
        setup_encrypt()
    if sys.argv[1] == '-d':
        setup_decrypt()
    else: sys.exit(2)

if __name__ == "__main__":
    parse_args()
