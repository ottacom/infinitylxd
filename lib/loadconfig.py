import configparser
import sys


def load_configuration():
    global server
    global username
    global password
    global protocol
    global port
    global search
    global gid_name
    global gid_number
    global trusted_domains
    global smtpserver
    global smtpsender
    try:
            defaultsettings  =  configparser.ConfigParser()
            defaultsettings.read("./conf/infinitylxd.conf")
            server = defaultsettings.get('ldap', 'ldap_server')
            username = defaultsettings.get('ldap', 'ldap_username')
            password = defaultsettings.get('ldap', 'ldap_password')
            protocol = defaultsettings.get('ldap', 'ldap_protocol')
            port = defaultsettings.get('ldap', 'ldap_port')
            search = defaultsettings.get('ldap', 'ldap_search')
            gid_name= defaultsettings.get('ldap', 'ldap_gid_name')
            gid_number = defaultsettings.get('ldap', 'ldap_gid_number')
	    trusted_domains = defaultsettings.get('security','trusted_domains')
	    smtpsender = defaultsettings.get('smtp','smtpsender')
	    smtpserver = defaultsettings.get('smtp','smtpserver')
            if not server:
                    print "The ldapserver is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
	    
            if not username:
		    print "The ldap_username is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
            if not password:
                    print "The ldap_password is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
	    if not protocol:
                    print "The ldap_protocol is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
	    if not port:
                    print "The ldap_port is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
	    if not search:
                    print "The ldap_search is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
	    if not gid_name:
                    print "The ldap_gid_name (gruop name) is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
	    if not gid_number:
                    print "The ldap_gid_number (gruop id) is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
            if not trusted_domains:
                    print "The trusted_domains is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
	    if not smtpsender:
                    print "The smtpsender address is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)
	    if not smtpserver:
                    print "The smtp server is mandatory please check infinitylxd.conf"
                    quit()
                    sys.exit(1)


    except Exception, e:
        print e
        print "Something is wrong into the configuration file, please take a look on infinitylxd.conf"
        sys.exit(1)


def ldap_server():
	return server
def ldap_username():
	return username
def ldap_password():
        return password
def ldap_protocol():
	return protocol
def ldap_port():
	return port
def ldap_search():
        return search
def ldap_gid_name():
        return gid_name
def ldap_gid_number():
        return gid_number
def trusted_domains():
        return trusted_domains
def smtpsender():
	return smtpsender
def smtpserver():
	return smtpserver
