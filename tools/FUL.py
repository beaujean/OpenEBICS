import os
import re
import sys
import zlib
import pytz
import array
import hashlib
import datetime
import requests
import binascii
from lxml import etree
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCipher
from base64 import b64encode, b64decode
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
Tpl_FUL_us = TplEnv.get_template('FUL-usersign.xml')
Tpl_HPB_sinfo = TplEnv.get_template('HPB-sinfo.xml')

# Send an HBP request for each user
for user in cfg['Users']:
    if 'transport' in cfg['Users'][user]:
        print ('Transporter:',user,'->',cfg['Users'][user]['UserID'])
    if 'signature' in cfg['Users'][user]:
        print ('Signature:',user,'->',cfg['Users'][user]['UserID'])
        continue
    UserID = cfg['Users'][user]['UserID']

    # Read and zip file
    sdd_content = open(cfg['upload'], 'rb').read()
    sdd_zip = zlib.compress(sdd_content, 9)
    sdd_zip = OEcert.appendBitPadding(sdd_zip)
    # Load bank certs
    bank_auth_cert = OEcert.get_cert_info_file('certs/'+cfg['Server']['HostID']+'/auth.crt')
    bank_encr_cert = OEcert.get_cert_info_file('certs/'+cfg['Server']['HostID']+'/crypt.crt')
    # Generate a ramdom key
    iv = "\0" * AES.block_size
    aes_key = binascii.hexlify(os.urandom(16)).upper()
    aes_hex = binascii.unhexlify(aes_key)
    # Load bank encr key
    encr_rsa_key = RSA.construct((bank_encr_cert['Modulus'], bank_encr_cert['Exponent']))
    aes_key_encrypt = PKCipher.new(encr_rsa_key).encrypt(aes_hex)
    aes_key_b64 = b64encode(aes_key_encrypt).decode()
    # Encrypt file
    sdd_encrypt = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(sdd_zip)
    #sdd_b64 = b64encode(sdd_encrypt) # XXX decode or no ? XXX
    sdd_b64 = b64encode(sdd_encrypt).decode()
    #sdd_segs = [ sdd_b64[a:a+1024*1024] for a in range(0,len(sdd_b64), 1024*1024) ] # Cut file into segments 1024*1024
    sdd_segs = [ sdd_b64[a:a+256*1024] for a in range(0,len(sdd_b64), 256*1024) ] # Cut file into segments 256*1024 for testing purposes
    sdd_num_segs = len(sdd_segs)

    # SignatureData
    order_data_string = sdd_content.decode().replace('\n', '').replace('\r', '').replace(chr(26), '')
    signed_info = OEcert.sign('certs/'+user+'/sign.key', order_data_string)
    signed_info_b64 = b64encode(signed_info)

    xml_FUL_us = Tpl_FUL_us.render(HostID = cfg['Server']['HostID'],
                                    PartnerID = cfg['Server']['PartnerID'],
                                    signed_info_b64 = signed_info_b64)
    #print (xml_FUL_us)

    signed_info_zip = zlib.compress(xml_FUL_us.encode(), 9)
    signed_info_zip = OEcert.appendBitPadding(signed_info_zip)
    iv = "\0" * AES.block_size
    signed_info_encrypt = AES.new(binascii.unhexlify(aes_key), AES.MODE_CBC, iv).encrypt(signed_info_zip)
    signed_info_b64 = b64encode(signed_info_encrypt).decode()

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
                                OrderID = 'A001',
                                FileFormat = 'pain.008.001.02.xsd',
                                Segments = sdd_num_segs,
                                BankAuthKey = bank_auth_cert['HashKey'],
                                BankEncrKey = bank_encr_cert['HashKey'],
                                TransactionKey = aes_key_b64,
                                SignatureData = signed_info_b64)

    # SHA256 Hash
    xml_hash = hashlib.sha256(xml_FUL.encode()).digest()
    # Base64
    xml_b64 = b64encode(xml_hash).decode()
    # Parsing HPB sign info template
    xml_HPB_sinfo = Tpl_HPB_sinfo.render(xml_b64 = xml_b64)
    crypt = OEcert.sign('certs/'+user+'/auth.key', xml_HPB_sinfo)
    crypt_b64 = b64encode(crypt).decode()
    auth_signature = '<AuthSignature>\n'+xml_HPB_sinfo+'\n'+'<SignatureValue>'+crypt_b64+'</SignatureValue>\n</AuthSignature>'
    #print (auth_signature)
    xml_FUL = xml_FUL.replace('<AuthSignature/>', auth_signature)
    print (xml_FUL)

    if 'Cert' in cfg['Server']:
        response = requests.post(cfg['Server']['URL'], cert=cfg['Server']['Cert'], data=xml_FUL.encode())
    else:
        response = requests.post(cfg['Server']['URL'], xml_FUL.encode())

    print (response.text)

    #xml_text = re.sub('xmlns="[^"]+"', '', response.text)
    #ebixml = etree.fromstring(xml_text.encode())
    #TransactionKey = ebixml.xpath("//body/DataTransfer/DataEncryptionInfo/TransactionKey/text()")[0]
    #OrderData = ebixml.xpath("//body/DataTransfer/OrderData/text()")[0]

