from jinja2 import Environment, FileSystemLoader

TplEnv = Environment(loader=FileSystemLoader('xml/'))

Template = TplEnv.get_template('HEV.xml')

HostID = 'plop'

print (Template.render(HostID=HostID))

