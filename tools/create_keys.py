import os
import sys
import pprint
import subprocess
sys.path.append('./libs/')
import OpenEBICS

cfg = OpenEBICS.config()

# Creating keys for each users defined in the config file
for user in sorted(cfg['Users']):
    print ('Creating keys for user '+user+' ('+cfg['Users'][user]['UserID']+')')
    userdir = 'certs/'+user
    # creating directories
    if not os.path.exists(userdir):
        os.makedirs(userdir)
    
    # creating keys
    for key in ['auth', 'crypt', 'sign']:
        crtfile = userdir+'/'+key+'.crt'
        keyfile = userdir+'/'+key+'.key'
        # keys already exists ?
        if os.path.exists(crtfile) or os.path.exists(keyfile):
            print ('crt file',crtfile,'or key file',keyfile,'already exists')
            next
        else:
            command = 'openssl req -x509 -nodes -days 730 -newkey rsa:2048 -out '+userdir+'/'+key+'.crt -keyout '+userdir+'/'+key+'.key -subj "/C=FR/ST=France/L=Paris/O='+cfg['Company']+'/OU='+cfg['Company']+'/CN='+user+'"'
            print (command)
            p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            print (output, err)

