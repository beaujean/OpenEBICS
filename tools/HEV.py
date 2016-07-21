import sys
import dumper
import requests
import xml.etree.ElementTree as ET
from jinja2 import Environment, FileSystemLoader
sys.path.append('./libs/')
import OpenEBICS

cfg = OpenEBICS.config()

# Parse Template
TplEnv = Environment(loader=FileSystemLoader('xml/'))
Template = TplEnv.get_template('HEV.xml')

xml = Template.render(HostID=cfg['Server']['HostID'])

if 'Cert' in cfg['Server']:
    response = requests.post(cfg['Server']['URL'], cert=cfg['Server']['Cert'], data=xml)
else:
    response = requests.post(cfg['Server']['URL'], xml)

#print (response.text)
ebixml = ET.fromstring(response.text)

#for child in ebixml:
#    print (child.tag,' -> ',child.attrib, ' txt: ', child.text)

for version in ebixml.findall('{http://www.ebics.org/H000}VersionNumber'):
    print ('Protocol:',version.get('ProtocolVersion'),'Version:',version.text)

