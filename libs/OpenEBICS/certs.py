import hashlib
import OpenSSL.crypto
from base64 import b64encode
from Crypto.Util import asn1
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCSign
from Crypto.Util.number import long_to_bytes

key_versions = {'auth'  : 'X002',
                'crypt' : 'E002',
                'sign'  : 'A005'}
key_names = {'auth'  : 'Authentification',
             'crypt' : 'Chiffrement',
             'sign'  : 'Signature'}

AES_blocksize = 16
# Functions from Padding package not working with Python3...
def paddingLength(str_len, blocksize=AES_blocksize):
    assert 0 < blocksize < 255, 'blocksize must be between 0 and 255'
    assert str_len > 0 , 'string length should be non-negative'
    pad_len = blocksize - (str_len % blocksize)
    return pad_len

def appendBitPadding(datas, blocksize=AES_blocksize):
    pad_len = paddingLength(len(datas), blocksize) - 1
    padding = chr(0x80)+'\0'*pad_len
    return datas + padding.encode('latin_1')

def get_cert_info_file(cert_file):
    # Open cert file
    cert_string = open(cert_file, 'rt').read()
    return get_cert_info(cert_string)

# Fetch useful informations from certs files
def get_cert_info(cert_string):
    cert = {}
    c = OpenSSL.crypto
    cert_data = c.load_certificate(c.FILETYPE_PEM, cert_string)
    # Format cert string as EBICS needs it
    cert['Letter'] = cert_string
    cert_string = cert_string.replace('-----BEGIN CERTIFICATE-----', '')
    cert_string = cert_string.replace('-----END CERTIFICATE-----', '')
    cert_string = cert_string.replace("\n", '')
    cert['Cert'] = cert_string

    # Get cert infos
    cert['Issuer'] = cert_data.get_issuer().CN
    cert['SerialNumber'] = cert_data.get_serial_number()
    cert['Digest'] = cert_data.digest('SHA256').decode()
    Pubkey = cert_data.get_pubkey()

    # Only works for RSA (I think...) <== XXX doesn't work with Python3
    #if Pubkey.type()!=c.TYPE_RSA:
    #    raise Exception('Sorry, EBICS can only handle RSA keys.')

    # Get Modulus and Exponent from X509 object
    pub_asn1 = c.dump_privatekey(c.FILETYPE_ASN1, Pubkey)
    # Decode DER
    pub_der = asn1.DerSequence()
    pub_der.decode(pub_asn1)
    # Finally modulus / Exponent !
    cert['Modulus'] = pub_der[1]
    cert['Exponent'] = pub_der[2]
    cert['Mod_b64'] = b64encode(long_to_bytes(pub_der[1])).decode()
    cert['Exp_b64'] = b64encode(long_to_bytes(pub_der[2])).decode()

    exp_hex = str(hex(pub_der[2]))[2:]
    mod_hex = str(hex(pub_der[1]))[2:]
    hash_key = exp_hex+' '+mod_hex
    if hash_key[0] == '0':
        hash_key = hash_key[1:]
    cert['HashKey'] = b64encode(hashlib.sha256(hash_key.encode()).digest()).decode()

    return cert

def get_names(type):
    return {'version': key_versions[type], 'name': key_names[type]}

def sign(key_file, string):
    # Open key file
    st_key = open(key_file, 'rt').read()
    rsakey = RSA.importKey(st_key)
    signer = PKCSign.new(rsakey)
    # Sign the SHA256 digested string
    signed = signer.sign(SHA256.new(string.encode()))
    return signed

