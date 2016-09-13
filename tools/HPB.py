import io
import sys
import zlib
import pytz
import base64
import codecs
import hashlib
import datetime
from datetime import time, tzinfo
import requests
import xml.etree.ElementTree as ET
from jinja2 import Environment, FileSystemLoader
sys.path.append('./libs/')
import OpenEBICS
import OpenEBICS.certs as OEcert

cfg = OpenEBICS.config()

# Opening templates
TplEnv = Environment(loader=FileSystemLoader('xml/'))
Tpl_HPB = TplEnv.get_template('HPB.xml')
Tpl_HPB_header = TplEnv.get_template('HPB-header.xml')
Tpl_HPB_sinfo = TplEnv.get_template('HPB-sinfo.xml')

# Send an HBP request for each user
for user in cfg['Users']:

    if 'transport' in cfg['Users'][user]:
        print ('Transporter:',user,'->',cfg['Users'][user]['UserID'])
    if 'signature' in cfg['Users'][user]:
        print ('Signature:',user,'->',cfg['Users'][user]['UserID'])
        continue
    UserID = cfg['Users'][user]['UserID']

    # 2016-07-07T13:26:01.592+01:00
    TimeStamp = datetime.datetime.now(tz=pytz.timezone('Europe/Paris')).isoformat('T')
    # XXX Generate a unique Nonce on each request XXX
    Nonce = 'D4EFFCDC8394C43A157173E5412222FF'

    # Parsing HPB header template
    xml_HPB_header = Tpl_HPB_header.render(HostID = cfg['Server']['HostID'],
                            Nonce = Nonce,
                            TimeStamp = TimeStamp,
                            PartnerID = cfg['Server']['PartnerID'],
                            UserID = UserID )
    #print (xml_HPB_header)

    # SHA256 Hash
    xml_hash = hashlib.sha256(xml_HPB_header.encode()).digest()
    # Base64
    xml_b64 = base64.b64encode(xml_hash).decode()

    # Parsing HPB sign info template
    xml_HPB_sinfo = Tpl_HPB_sinfo.render(xml_b64 = xml_b64)
    #print (xml_HPB_sinfo)

    crypt = OEcert.sign('certs/'+user+'/auth.key', xml_HPB_sinfo)
    crypt_hex = codecs.encode(crypt, 'hex').decode().upper()
    crypt_b64 = base64.b64encode(crypt).decode()

    # Parsing HPB final template
    xml_HPB = Tpl_HPB.render(xml_HPB_header = xml_HPB_header,
            xml_HPB_sinfo = xml_HPB_sinfo,
            crypt_b64 = crypt_b64)
    #print (xml_HPB)

    if 'Cert' in cfg['Server']:
        response = requests.post(cfg['Server']['URL'], cert=cfg['Server']['Cert'], data=xml_HPB.encode())
    else:
        response = requests.post(cfg['Server']['URL'], xml_HPB.encode())

    print (response.text)

    #ebixml = ET.fromstring(response.text)
    #
    ##for child in ebixml:
    ##    print (child.tag,' -> ',child.attrib, ' txt: ', child.text)
    #
    #for version in ebixml.findall('{http://www.ebics.org/H000}VersionNumber'):
    #    print ('Protocol:',version.get('ProtocolVersion'),'Version:',version.text)

