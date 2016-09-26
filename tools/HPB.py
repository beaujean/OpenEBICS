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
from lxml import etree
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
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
    # D4EFFCDC8394C43A157173E5412222FF
    Nonce = binascii.hexlify(os.urandom(16)).upper().decode()

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
    #crypt_hex = codecs.encode(crypt, 'hex').decode().upper()
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

    xml_text = re.sub('xmlns="[^"]+"', '', response.text)

    #ns = {'ebics': 'http://www.ebics.org/H003'}
    ebixml = etree.fromstring(xml_text.encode())
    TransactionKey = ebixml.xpath("//body/DataTransfer/DataEncryptionInfo/TransactionKey/text()")[0]
    OrderData = ebixml.xpath("//body/DataTransfer/OrderData/text()")[0]
    
    # Open private key file
    st_priv_key = open('certs/'+user+'/crypt.key', 'rt').read()
    priv_key = RSA.importKey(st_priv_key)
    # Decrypt transaction key
    trans_key = priv_key.decrypt(base64.b64decode(TransactionKey))
    trans_key_hex = binascii.hexlify(trans_key)
    aes_key = trans_key_hex[len(trans_key_hex)-32:]
    aes_key = binascii.unhexlify(aes_key)

    # the iv paramater on AES cipher intialization is put to \0: Crypto lib doc says it's nt secure (even if IV should not be secret)
    iv = "\0" * AES.block_size
    # Decrypt OrderData
    zipdata = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(base64.b64decode(OrderData))
    zipdata_hexa = array.array('B', zipdata)
    bank_datas = zlib.decompress(zipdata_hexa)

    print (bank_datas.decode())

