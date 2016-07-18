import yaml

with open("ebics.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)

for section in cfg:
    print(section)
    print(cfg[section])

