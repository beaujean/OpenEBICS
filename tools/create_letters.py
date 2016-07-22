import os
import sys
import pytz
import datetime
from jinja2 import Environment, FileSystemLoader
sys.path.append('./libs/')
import OpenEBICS
import OpenEBICS.certs as OEcert

cfg = OpenEBICS.config()

# Opening templates
TplEnv = Environment(loader=FileSystemLoader('xml/'))
Tpl_letter = TplEnv.get_template('letter.txt')

# Creating keys for each users defined in the config file
for user in sorted(cfg['Users']):
    print ('Creating letter for user '+user+' ('+cfg['Users'][user]['UserID']+')')
    userdir = 'certs/'+user
    # creating directories
    if not os.path.exists(userdir):
        os.makedirs(userdir)
    
    # creating letter for each key...
    for key in ['auth', 'crypt', 'sign']:
        crtfile = userdir+'/'+key+'.crt'
        letterfile = userdir+'/'+key+'.txt'
        # keys already exists ?
        if os.path.exists(letterfile):
            print ('letter file',letterfile,'already exists')
            next
        else:
            # Getting useful certificate informations
            cert = OEcert.get_cert_info(crtfile)
            Date = datetime.datetime.now(tz=pytz.timezone('Europe/Paris')).strftime("%d/%m/%Y %H:%M")
            # Parsing letter templates
            txt_letter = Tpl_letter.render(HostID = cfg['Server']['HostID'],
                PartnerID = cfg['Server']['PartnerID'],
                UserID = cfg['Users'][user]['UserID'],
                BankName = cfg['Server']['Name'],
                Certificate = cert['Letter'],
                Version = OEcert.get_names(key)['version'],
                VersionName = OEcert.get_names(key)['name'],
                User = user,
                Date = Date,
                Digest1 = cert['Digest'][:47].replace(':', ' '),
                Digest2 = cert['Digest'][48:].replace(':', ' '))
            print (txt_letter)

