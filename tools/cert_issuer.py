import OpenSSL.crypto
import dumper
import pprint

c=OpenSSL.crypto

st_cert=open('certs/abeaujean/auth.crt', 'rt').read()
cert=c.load_certificate(c.FILETYPE_PEM, st_cert)

st_key=open('certs/abeaujean/auth.key', 'rt').read()
key=c.load_privatekey(c.FILETYPE_PEM, st_key)

iss = cert.get_issuer()

print (iss.CN)
print (iss.O)

print (key.type())
print (key.bits())

