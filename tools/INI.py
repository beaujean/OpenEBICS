import sys
import zlib
import pytz
import base64
import datetime
import requests
import xml.etree.ElementTree as ET
from jinja2 import Environment, FileSystemLoader
sys.path.append('./libs/')
import OpenEBICS
import OpenEBICS.certs as OEcert

cfg = OpenEBICS.config()

# Opening templates
TplEnv = Environment(loader=FileSystemLoader('xml/'))
Tpl_INI = TplEnv.get_template('INI.xml')
Tpl_A005 = TplEnv.get_template('A005.xml')

# Send an INI request for each user
for user in cfg['Users']:

    if 'transport' in cfg['Users'][user]:
        print ('Transporter:',user,'->',cfg['Users'][user]['UserID'])
    if 'signature' in cfg['Users'][user]:
        print ('Signature:',user,'->',cfg['Users'][user]['UserID'])
    UserID = cfg['Users'][user]['UserID']

    # Getting useful certificate informations
    auth_cert = OEcert.get_cert_info_file('certs/'+user+'/sign.crt')

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
    #print (xml_A005)

    # Gzip and base64 A005 auth cert
    zip_A005 = zlib.compress(xml_A005.encode())
    b64_A005 = base64.b64encode(zip_A005)

    # Parsing INI templates
    xml_INI = Tpl_INI.render(HostID = cfg['Server']['HostID'],
                            PartnerID = cfg['Server']['PartnerID'],
                            UserID = UserID,
                            OrderID = 'A001',
                            OrderData = b64_A005.decode())
    #print (xml_INI)

    if 'Cert' in cfg['Server']:
        response = requests.post(cfg['Server']['URL'], cert=cfg['Server']['Cert'], data=xml_INI.encode())
    else:
        response = requests.post(cfg['Server']['URL'], xml_INI.encode())
    #print (response.text)

    ebixml = ET.fromstring(response.text)
    ns = {'ebics': 'http://www.ebics.org/H003'}
    
    for header in ebixml.findall('ebics:header', ns):
        for mutable in header.findall('ebics:mutable', ns):
            ReturnCode = mutable.find('ebics:ReturnCode', ns)
            print ('\tReturnCode:',ReturnCode.text)
            ReportText = mutable.find('ebics:ReportText', ns)
            print ('\tReportText:',ReportText.text)
    for body in ebixml.findall('ebics:body', ns):
        ReturnCode = body.find('ebics:ReturnCode', ns)
        print ('\tReturnCode:',ReturnCode.text)

