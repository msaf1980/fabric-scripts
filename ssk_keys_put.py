import sys
import os
import argparse

# grep hostname: network.yml | awk '{ print $2 }' > network.hosts

from getpass import getpass
from fabric import Connection

SSH_HOME  = "~/.ssh"
AUTH_KEYS = "~/.ssh/authorized_keys"

def get_public_key(key_file):

    with open(os.path.expanduser(key_file)) as fd:
        key = fd.readline().strip()
    return key

# ---------------------------------------------------------------------------- #

def set_hosts(hosts, filename):
    with open(os.path.expanduser(filename)) as fd:
        for host in fd.readlines():
            if not host.startswith('#'): hosts.append(host.strip())

def add_key(hosts, user, password, filename):
    commands = 'mkdir -p %s; chmod 700 %s; touch %s;  if ! grep -w "%s" %s >/dev/null; then echo "%s" >> %s; fi; chmod 644 %s'

    pub_key = get_public_key(filename)
    t = (SSH_HOME, SSH_HOME, AUTH_KEYS, pub_key, AUTH_KEYS, pub_key, AUTH_KEYS, AUTH_KEYS)
    command = commands % t
    print(command)
    connect_args = {}
    if not password is None:
        connect_args["password"] = password
        
    for host in hosts:
        try:
            if user is None:
                conn_str = host
            else:
                conn_str = "%s@%s" % (user, host)
            c = Connection(host, user=user, connect_kwargs=connect_args)
            c.run(command)
            sys.stdout.write("DONE on %s\n" % conn_str)
        except Exception as e:
            sys.stderr.write("ERROR on %s: %s\n" % (conn_str, str(e)))


if __name__ == "__main__":    
    parser = argparse.ArgumentParser(description='''
Deploy ssh public key.For form hosts file from network YAML config:
	grep hostname: network.yml | awk '{ print $2 }' > network.hosts
''')

    parser.add_argument('-t', '--host', dest='hosts', action='append', type=str, default=None,\
                         help='hosts file')

    parser.add_argument('-f', '--file', dest='hosts_file', action='store', type=str, default=None,\
                         help='hosts file')

    parser.add_argument('-u', '--user', dest='user', action='store', type=str, default=None,\
                         help='username')
                         
    parser.add_argument('-p', '--password', dest='password', action='store', type=str, default=None,\
                         help='password')
                         
    parser.add_argument('-i', '--input', dest='input', action='store_true', default=False,\
                         help='input a password')    

    parser.add_argument('-k', '--key', dest='key', action='store', type=str, default=None,\
                         help='ssh public key')                          

    args = parser.parse_args()

    hosts = []
    user = None
    password = None
    key = "~/.ssh/id_rsa.pub"
    
    if not args.hosts is None:
        hosts.extend(args.hosts)

    if not args.hosts_file is None:
        set_hosts(hosts, args.hosts_file)

    if not args.user is None:
        user = args.user
        
    if not args.password is None:
        password = args.password
    
    if args.input:
        password = getpass('Enter ssh password:')

    if not args.key is None:
        key = args.key

    if hosts is None:
        set_hosts(hosts, "~/.hosts")

    if len(hosts) > 0:
        add_key(hosts, user, password, filename=key)
