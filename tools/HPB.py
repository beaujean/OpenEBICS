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
sign_cert = OEcert.get_cert_info('certs/'+User+'/sign.crt')

Nonce = 'D4EFFCDC8394C43A157173E5411111DD'
Digest = 'dFQbrUfC2LBWgWBjPM2pAKlGcIO6ud+0N5iPY5ujob0='
Signature = 'Jm2gC+VwTSdnyNQFrZBdbYmTRp50ik9jOzsIBZ1kD+c6icN3uLFMAVtNHD1UO6CxROcbYFSpiXxjDbZQfae8HThYnKyw670eLSDY3wAEC0SEqLDl9E5GBKUU4/Uof75R6+PKh8DFrGlijFiBPiUAiG1v+tIIGQry+u9mi5edcbmHEA3zSU0IUQ3B8MfMuly12vqumNUkTvsRoy54XkGV05tDd7BBNPIcYTOWYWFiI1bWGqj1aW70yBPBPaY1wAru+gJJBYkEqyFdH+WkoxpIOAODclq4BOvv4bg4Q+iilqZRDfZHZ7N1hLCny7zpMmeXCnJMh14Ke6W11a9Idsi4qw=='

# 2016-07-07T13:26:01.592+01:00
TimeStamp = datetime.datetime.now(tz=pytz.timezone('Europe/Paris')).isoformat('T')

# Opening templates
TplEnv = Environment(loader=FileSystemLoader('xml/'))
Tpl_HPB = TplEnv.get_template('HPB.xml')

# Parsing INI templates
xml_HPB = Tpl_HPB.render(HostID = cfg['Server']['HostID'],
                        PartnerID = cfg['Server']['PartnerID'],
                        UserID = UserID,
                        Nonce = Nonce,
                        TimeStamp = TimeStamp,
                        OrderID = 'A001',
                        Digest = Digest,
                        Signature = Signature)
print (xml_HPB)

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

