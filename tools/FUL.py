import os
import re
import sys
import zlib
import pytz
import array
import base64
import hashlib
import datetime
import requests
import binascii
from Padding import *
from lxml import etree
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from jinja2 import Environment, FileSystemLoader
sys.path.append('./libs/')
import OpenEBICS
import OpenEBICS.certs as OEcert

cfg = OpenEBICS.config()

if 'upload' in cfg:
    print ('Uploading file: ', cfg['upload'])
else:
    print ('FUL error: no file to upload')
    sys.exit(1)

# Opening templates
TplEnv = Environment(loader=FileSystemLoader('xml/'))
Tpl_FUL = TplEnv.get_template('FUL.xml')

# Send an HBP request for each user
for user in cfg['Users']:
    if 'transport' in cfg['Users'][user]:
        print ('Transporter:',user,'->',cfg['Users'][user]['UserID'])
    if 'signature' in cfg['Users'][user]:
        print ('Signature:',user,'->',cfg['Users'][user]['UserID'])
        continue
    UserID = cfg['Users'][user]['UserID']

    sdd_content = open(cfg['upload'], 'rb').read()
    sdd_zip = zlib.compress(sdd_content, 9)
    #sdd_zip = appendBitPadding(sdd_zip)
    iv = "\0" * AES.block_size
    # Open private key file
    st_priv_key = open('certs/'+user+'/crypt.key', 'rt').read()
    priv_key = RSA.importKey(st_priv_key)
    # Encrypt file
    sdd_encrypt = AES.new(priv_key, AES.MODE_CBC, iv).encrypt(sdd_zip)
    sdd_b64 = base64.b64encode(sdd_encrypt)
    sdd_segs = [ sdd_b64[a:a+chunksize] for a in range(0,len(sdd_b64), 1024*1024) ] # Cut file into segments

    # 2016-07-07T13:26:01.592+01:00
    TimeStamp = datetime.datetime.now(tz=pytz.timezone('Europe/Paris')).isoformat('T')
    # D4EFFCDC8394C43A157173E5412222FF
    Nonce = binascii.hexlify(os.urandom(16)).upper().decode()

    # Parsing HPB header template
    xml_FUL = Tpl_FUL.render(HostID = cfg['Server']['HostID'],
                                Nonce = Nonce,
                                TimeStamp = TimeStamp,
                                PartnerID = cfg['Server']['PartnerID'],
                                UserID = UserID,
                                OrderID = 'A001')
    print (xml_FUL)

#    # SHA256 Hash
#    xml_hash = hashlib.sha256(xml_HPB_header.encode()).digest()
#    # Base64
#    xml_b64 = base64.b64encode(xml_hash).decode()
#
#    # Parsing HPB sign info template
#    xml_HPB_sinfo = Tpl_HPB_sinfo.render(xml_b64 = xml_b64)
#    #print (xml_HPB_sinfo)
#
#    crypt = OEcert.sign('certs/'+user+'/auth.key', xml_HPB_sinfo)
#    crypt_b64 = base64.b64encode(crypt).decode()
#
#    if 'Cert' in cfg['Server']:
#        response = requests.post(cfg['Server']['URL'], cert=cfg['Server']['Cert'], data=xml_HPB.encode())
#    else:
#        response = requests.post(cfg['Server']['URL'], xml_HPB.encode())
#
#    xml_text = re.sub('xmlns="[^"]+"', '', response.text)

    #ebixml = etree.fromstring(xml_text.encode())
    #TransactionKey = ebixml.xpath("//body/DataTransfer/DataEncryptionInfo/TransactionKey/text()")[0]
    #OrderData = ebixml.xpath("//body/DataTransfer/OrderData/text()")[0]

