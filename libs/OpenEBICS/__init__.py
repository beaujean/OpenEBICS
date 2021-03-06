# OpenEBICS / __ini__.py
import sys
import yaml

# Choose and load config file
def config():

    if sys.argv and sys.argv[1:]:
        cfgfile = sys.argv[1]
    else:
        cfgfile = 'ebics.yml'

    # Loading the EBICS config file
    try:
        with open(cfgfile, 'r') as ymlfile:
            cfg = yaml.load(ymlfile)
    except IOError:
        print ('Error: the config file',cfgfile,'doesn''t exists')
        sys.exit(1)

    # Upload file ?
    if sys.argv and sys.argv[2:]:
        cfg['upload'] = sys.argv[2]

    return cfg

