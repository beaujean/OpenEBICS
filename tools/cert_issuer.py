import sys
import OpenSSL.crypto
from Crypto.Util import asn1
import dumper
import pprint
sys.path.append('./libs/')
import OpenEBICS

cfg = OpenEBICS.config()

# Parsing users args
for user in cfg['Users']:
    if 'transport' in cfg['Users'][user]:
        print ('Transporter:',user,'->',cfg['Users'][user]['UserID'])
        User = user
        UserID = cfg['Users'][user]['UserID']

c=OpenSSL.crypto

st_cert=open('certs/'+User+'/auth.crt', 'rt').read()
cert=c.load_certificate(c.FILETYPE_PEM, st_cert)

st_key=open('certs/'+User+'/auth.key', 'rt').read()
key=c.load_privatekey(c.FILETYPE_PEM, st_key)

iss = cert.get_issuer()

print (iss.CN)
print (iss.O)

#print (key.type())
print (key.bits())

print (cert.get_serial_number())

pub = cert.get_pubkey()

# Only works for RSA (I think)
#if pub.type()!=c.TYPE_RSA:
#    raise Exception('Can only handle RSA keys')

# This seems to work with public as well
pub_asn1=c.dump_privatekey(c.FILETYPE_ASN1, pub)
# Decode DER
pub_der=asn1.DerSequence()
pub_der.decode(pub_asn1)
# Get the modulus
pub_modulus=pub_der[1]
pub_exponent=pub_der[2]
print (pub_modulus)
print (pub_exponent)

