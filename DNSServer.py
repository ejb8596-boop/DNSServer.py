import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast
import dns.name
import dns.rrset


def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key


def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data


# FIXED: decrypt accepts bytes OR a string (coming from TXT record)
def decrypt_with_aes(encrypted_data, password, salt):
    # if someone passed the decoded txt string, convert back to bytes
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')

    key = generate_aes_key(password, salt)
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')
    except InvalidToken as e:
        # clearer error msg for debugging but don't leak secret
        print("decrypt error! Type:", type(e), "Value:", "Something is wrong with how you are storing the token")
        return None


salt = b'Tandon'
password = 'ejb8596@nyu.edu'   # replace if you need different nyu email
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt)
# We test decrypt right away using the bytes returned by encrypt
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)


def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()


dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },

    # assignment ones
    'safebank.com.': {
        dns


if __name__ == '__main__':
    run_dns_server_user()
    #print("Encrypted:", encrypted_value)
    #print("Decrypted:", decrypted_value)
