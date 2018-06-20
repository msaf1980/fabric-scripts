import sys
import yaml
import argparse

from getpass import getpass
from fabric import Connection

class RHEL7:
	@staticmethod
	def hostname_set(hostname):
		return 'nmcli general hostname %s' % hostname

	@staticmethod
	def hostname_appy():
		return 'systemctl restart systemd-hostnamed'

	@staticmethod
	def ifaces():
		return 'nmcli con show && ip addr'

	@staticmethod
	def iface_rename(oldname, newname):
		return 'nmcli con modify "%s" connection.id %s 2>/dev/null || true' % (oldname, newname)

	@staticmethod
	def iface_set_ip4(name, ip, network, gw = None):
		s = 'nmcli con mod "%s" ip4 %s/%s' % (name, ip, network)
		if not gw is None:
			s += ' gw4 %s' % gw
		return s

	@staticmethod
	def iface_set_dns4(name, dns):
		return 'nmcli con mod "%s" ipv4.dns "%s"' % (name, dns)

	@staticmethod
	def iface_set_dns4_search(name, search):
		return 'nmcli con mod "%s" ipv4.dns-search "%s"' % (name, search)

	@staticmethod
	def network_restart():
		#return 'nohup sh -c "systemctl stop network && systemctl start network"'
		return 'systemctl restart network && hostname && ip addr'
		#return 'nohup sh -c "ifdown %s && ifup %s"' % (iface, iface)

	@staticmethod
	def msg(host):
		print "old ip address %s may be leave as alias, remove like\n\tip addr del %s/NETWORK dev IFACE" % (host, host)

def configure(host, param, test):
	additional = { 'network', 'gw' }

	if param['os'] == "rhel7":
		os = RHEL7
	else:
		sys.stderr.write("ERROR: os %s not supported\n" % param['os'])
		sys.exit(1)

	precmds = []

	cmds = []
	postcmds = []

	restart = False

	if param.get('hostname'):
		cmds.append(os.hostname_set(param['hostname']))
		postcmds.append(os.hostname_appy())

	if param.get('interfaces'):
		for iface in param['interfaces']:
			iface_params = param['interfaces'][iface]
			#print iface_param
			for p in iface_params:
				if p == 'oldname':
					precmds.append(os.iface_rename(iface_params[p], iface))
					restart = True
				elif p == 'ip':
					cmds.append(os.iface_set_ip4(iface, iface_params[p], iface_params['network'], iface_params.get('gw')))
					restart = True
				elif p == 'dns':
					cmds.append(os.iface_set_dns4(iface, iface_params[p]))
					restart = True
				elif p == 'dns-search':
					cmds.append(os.iface_set_dns4_search(iface, iface_params[p]))
					restart = True
				elif not p in additional:
					raise ValueError('%s not supported in %s' % (p, iface))

	print "Execute on %s:" % host	
	for cmd in precmds:
		print cmd

	for cmd in cmds:
		print cmd

	for cmd in postcmds:
		print cmd

	if restart:
		print os.network_restart()

	if test:
		return

	password = getpass('Enter root password:')
	c = Connection(host, user='root', connect_kwargs={"password": password})
	c.run(os.ifaces())
	for cmd in precmds:
		c.run(cmd)

	for cmd in cmds:
		c.run(cmd)

	for cmd in postcmds:
		c.run(cmd)

	if restart:
		cmd = os.network_restart()
		try:
			c.run(cmd)
			os.msg(host)
		except Exception as e:
			print str(e)

# end configure

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Set network settings')

    parser.add_argument('-c', '--config', dest='config', action='store', type=str, required=True,\
                         help='YAML config file')

    parser.add_argument('-r', '--run', dest='run', action='store', type=str, required=True,\
                         help='run on host')

    parser.add_argument('-n', '--name', dest='name', action='store', type=str, required=True,\
                         help='name in config')

    parser.add_argument('-e', '--exec', dest='test', default=True, action='store_false',\
                         help='execute')


    args = parser.parse_args()

    with open(args.config, 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
        param = cfg[args.name]
        configure(args.run, param, args.test)    
        
