import base64
import OpenSSL.crypto
from Crypto.Util import asn1
from Crypto.Util.number import long_to_bytes

# Fetch useful informations from certs files
def get_cert_info(cert_file):
    cert = {}
    # Open cert file
    c = OpenSSL.crypto
    cert_string = open(cert_file, 'rt').read()
    cert_data = c.load_certificate(c.FILETYPE_PEM, cert_string)

    # Format cert string as EBICS needs it
    cert_string = cert_string.replace('-----BEGIN CERTIFICATE-----', '')
    cert_string = cert_string.replace('-----END CERTIFICATE-----', '')
    cert_string = cert_string.replace("\n", '')
    cert['Cert'] = cert_string

    # Get cert infos
    cert['Issuer'] = cert_data.get_issuer().CN
    cert['SerialNumber'] = cert_data.get_serial_number()
    Pubkey = cert_data.get_pubkey()

    # Get Modulus and Exponent from X509 object
    pub_asn1 = c.dump_privatekey(c.FILETYPE_ASN1, Pubkey)
    # Decode DER
    pub_der = asn1.DerSequence()
    pub_der.decode(pub_asn1)
    # Finally modulus / Exponent !
    cert['Modulus'] = base64.b64encode(long_to_bytes(pub_der[1])).decode()
    cert['Exponent'] = base64.b64encode(long_to_bytes(pub_der[2])).decode()
 
    return cert

