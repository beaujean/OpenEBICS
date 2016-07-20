import sys
import yaml
import zlib
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
sys.path.append('./libs/')
import OpenEBICS.certs as OEcert

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

# Getting useful certificate informations
auth_cert = OEcert.get_cert_info('certs/'+User+'/auth.crt')

# 2016-07-07T13:26:01.592+01:00
TimeStamp = datetime.datetime.now(tz=pytz.timezone('Europe/Paris')).isoformat('T')

# Parsing A005 templates
xml_A005 = Tpl_A005.render(HostID = cfg['Server']['HostID'],
                        PartnerID = cfg['Server']['PartnerID'],
                        UserID = UserID,
                        TimeStamp = TimeStamp,
                        IssuerName = auth_cert['Issuer'],
                        SerialNumber = auth_cert['SerialNumber'],
                        Certificate = auth_cert['Cert'],
                        Modulus = auth_cert['Modulus'],
                        Exponent = auth_cert['Exponent'])
print (xml_A005)

# Gzip and base64 A005 auth cert
zip_A005 = zlib.compress(xml_A005.encode())
b64_A005 = base64.b64encode(zip_A005)

# Parsing INI templates
xml_INI = Tpl_INI.render(HostID = cfg['Server']['HostID'],
                        PartnerID = cfg['Server']['PartnerID'],
                        UserID = UserID,
                        OrderID = 'A001',
                        OrderData = b64_A005.decode())
print (xml_INI)

if 'Cert' in cfg['Server']:
    response = requests.post(cfg['Server']['URL'], cert=cfg['Server']['Cert'], data=xml_INI.encode())
else:
    response = requests.post(cfg['Server']['URL'], xml_INI.encode())

print (response.text)

#ebixml = ET.fromstring(response.text)
#
##for child in ebixml:
##    print (child.tag,' -> ',child.attrib, ' txt: ', child.text)
#
#for version in ebixml.findall('{http://www.ebics.org/H000}VersionNumber'):
#    print ('Protocol:',version.get('ProtocolVersion'),'Version:',version.text)

