import sys
import zlib
import pytz
import base64
import datetime
from datetime import time, tzinfo
import requests
import xml.etree.ElementTree as ET
from jinja2 import Environment, FileSystemLoader
sys.path.append('./libs/')
import OpenEBICS
import OpenEBICS.certs as OEcert

cfg = OpenEBICS.config()

# Parsing users args
for user in cfg['Users']:
    if 'transport' in cfg['Users'][user]:
        print ('Transporter:',user,'->',cfg['Users'][user]['UserID'])
        User = user
        UserID = cfg['Users'][user]['UserID']

# Getting useful certificate informations
auth_cert = OEcert.get_cert_info('certs/'+User+'/auth.crt')
encr_cert = OEcert.get_cert_info('certs/'+User+'/crypt.crt')

# 2016-07-07T13:26:01.592+01:00
TimeStamp = datetime.datetime.now(tz=pytz.timezone('Europe/Paris')).isoformat('T')

# Opening templates
TplEnv = Environment(loader=FileSystemLoader('xml/'))
Tpl_HIA = TplEnv.get_template('HIA.xml')
Tpl_HIA_data = TplEnv.get_template('HIA-data.xml')

# Parsing A005 templates
xml_HIA_data = Tpl_HIA_data.render(HostID = cfg['Server']['HostID'],
                        PartnerID = cfg['Server']['PartnerID'],
                        UserID = UserID,
                        AuthIssuerName = auth_cert['Issuer'],
                        AuthSerialNumber = auth_cert['SerialNumber'],
                        AuthCertificate = auth_cert['Cert'],
                        AuthModulus = auth_cert['Modulus'],
                        AuthExponent = auth_cert['Exponent'],
                        EncrIssuerName = encr_cert['Issuer'],
                        EncrSerialNumber = encr_cert['SerialNumber'],
                        EncrCertificate = encr_cert['Cert'],
                        EncrModulus = encr_cert['Modulus'],
                        EncrExponent = encr_cert['Exponent'],
                        TimeStamp = TimeStamp)
print (xml_HIA_data)

# Gzip and base64 HIA data auth cert
zip_HIA_data = zlib.compress(xml_HIA_data.encode())
b64_HIA_data = base64.b64encode(zip_HIA_data)

# Parsing HIA templates
xml_HIA = Tpl_HIA.render(HostID = cfg['Server']['HostID'],
                        PartnerID = cfg['Server']['PartnerID'],
                        UserID = UserID,
                        OrderID = 'A001',
                        OrderData = b64_HIA_data.decode())
print (xml_HIA)

if 'Cert' in cfg['Server']:
    response = requests.post(cfg['Server']['URL'], cert=cfg['Server']['Cert'], data=xml_HIA.encode())
else:
    response = requests.post(cfg['Server']['URL'], xml_HIA.encode())

print (response.text)

#ebixml = ET.fromstring(response.text)
#
##for child in ebixml:
##    print (child.tag,' -> ',child.attrib, ' txt: ', child.text)
#
#for version in ebixml.findall('{http://www.ebics.org/H000}VersionNumber'):
#    print ('Protocol:',version.get('ProtocolVersion'),'Version:',version.text)

