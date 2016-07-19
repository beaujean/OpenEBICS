import sys
import yaml
import gzip
import pytz
import base64
import dumper
import datetime
from datetime import time, tzinfo
import requests
import OpenSSL.crypto
from Crypto.Util import asn1
import xml.etree.ElementTree as ET
from jinja2 import Environment, FileSystemLoader

if sys.argv and sys.argv[1:]:
    cfgfile = sys.argv[1]
else:
    cfgfile = 'ebics.yml'

# Loading the EBICS config file
with open(cfgfile, 'r') as ymlfile:
    cfg = yaml.load(ymlfile)

# Opening templates
TplEnv = Environment(loader=FileSystemLoader('xml/'))
Tpl_INI = TplEnv.get_template('INI.xml')
Tpl_A005 = TplEnv.get_template('A005.xml')

# Parsing users args
for user in cfg['Users']:
    if 'transport' in cfg['Users'][user]:
        print ('Transporter:',user,'->',cfg['Users'][user]['UserID'])
        User = user
        UserID = cfg['Users'][user]['UserID']

# Open "auth" certificate file
c = OpenSSL.crypto
st_cert = open('certs/'+User+'/auth.crt', 'rt').read()
cert = c.load_certificate(c.FILETYPE_PEM, st_cert)

# Format cert string as EBICS needs it
st_cert = st_cert.replace('-----BEGIN CERTIFICATE-----', '')
st_cert = st_cert.replace('-----END CERTIFICATE-----', '')
st_cert = st_cert.replace("\n", '')

# Get cert infos
Issuer = cert.get_issuer()
Pubkey = cert.get_pubkey()
SerialNumber = cert.get_serial_number()

# Get Modulus and Exponent from X509 object
pub_asn1 = c.dump_privatekey(c.FILETYPE_ASN1, Pubkey)
# Decode DER
pub_der = asn1.DerSequence()
pub_der.decode(pub_asn1)
# Finally modulus / Exponent !
Modulus = pub_der[1]
Exponent = pub_der[2]

# 2016-07-07T13:26:01.592+01:00
TimeStamp = datetime.datetime.now(tz=pytz.timezone('Europe/Paris')).isoformat('T')

# Parsing A005 templates
xml_A005 = Tpl_A005.render(HostID = cfg['Server']['HostID'],
                        PartnerID = cfg['Server']['PartnerID'],
                        UserID = UserID,
                        IssuerName = Issuer.CN,
                        SerialNumber = SerialNumber,
                        Certificate = st_cert,
                        TimeStamp = TimeStamp,
                        Modulus = base64.b64encode(str(Modulus).encode()).decode(),
                        Exponent = base64.b64encode(str(Exponent).encode()).decode())
                        #Exponent = str(Exponent))

zip_A005 = gzip.compress(xml_A005.encode())
b64_A005 = base64.b64encode(zip_A005)

# Parsing INI templates
xml_INI = Tpl_INI.render(HostID = cfg['Server']['HostID'],
                        PartnerID = cfg['Server']['PartnerID'],
                        UserID = UserID,
                        OrderID = 'B010',
                        OrderData = b64_A005.decode())
print (xml_INI)

if 'Cert' in cfg['Server']:
    response = requests.post(cfg['Server']['URL'], cert=cfg['Server']['Cert'], data=xml)
else:
    response = requests.post(cfg['Server']['URL'], xml_INI)

print (response.text)

#ebixml = ET.fromstring(response.text)
#
##for child in ebixml:
##    print (child.tag,' -> ',child.attrib, ' txt: ', child.text)
#
#for version in ebixml.findall('{http://www.ebics.org/H000}VersionNumber'):
#    print ('Protocol:',version.get('ProtocolVersion'),'Version:',version.text)

