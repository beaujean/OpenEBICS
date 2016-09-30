import sys
import OpenSSL.crypto
from Crypto.Util import asn1
from Crypto.PublicKey import RSA
import dumper
import base64
import pprint
import hashlib
sys.path.append('./libs/')
import OpenEBICS

cfg = OpenEBICS.config()

# Parsing users args
#for user in cfg['Users']:
#    if 'transport' in cfg['Users'][user]:
#        print ('Transporter:',user,'->',cfg['Users'][user]['UserID'])
#        User = user
#        UserID = cfg['Users'][user]['UserID']

#User = cfg['Server']['HostID']
User = cfg['Users'][user]

c=OpenSSL.crypto

st_cert=open('certs/'+User+'/auth.crt', 'rt').read()
cert=c.load_certificate(c.FILETYPE_PEM, st_cert)

st_key=open('certs/'+User+'/auth.key', 'rt').read()
private = RSA.importKey(st_key)
modulus = getattr(private.key, 'n')
private_exponent = getattr(private.key, 'd')
public_exponent = getattr(private.key, 'e')

print ('mod:',modulus)
print ('pub exp:',public_exponent)
print ('priv exp:',private_exponent)

iss = cert.get_issuer()

print ('CN:',iss.CN)
print ('0:',iss.O)

#print (key.type())
#print ('bits:',key.bits())

print ('SN:',cert.get_serial_number())

pub = cert.get_pubkey()
#priv = key.get_privkey()

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
print ('mod:',pub_modulus)
print ('pub exp:',pub_exponent)

digest = cert.digest('SHA256').decode()
print ('dig1:',digest[:47].replace(':', ' '))
print ('dig2:',digest[48:].replace(':', ' '))

e_hex_str = str(hex(pub_exponent))[2:]
n_hex_str = str(hex(pub_modulus))[2:]

s = e_hex_str+' '+n_hex_str
if s[0] == '0':
    s = s[1:]
res = base64.b64encode(hashlib.sha256(s.encode()).digest())
print (s, res)

