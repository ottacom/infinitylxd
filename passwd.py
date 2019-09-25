#!/usr/bin/env python

# -*- coding: utf-8 -*-

"""
Password change utility implementation based on sarge-based Skolelinux.

Author: Bjorn Ove Grotan <bjorn.ove@grotan.com>
Depends: python-ldap
May-depend: smbpasswd
"""

import sys
import os
import string,base64,random
from getpass import getuser,getpass

# Needed for generating encrypted passwords
import md5,sha,crypt

try:
    import ldap
    from ldap import modlist
except ImportError,ie:
    print "Python-ldap not install or missing in PYTHONPATH. Exiting..."
    sys.exit()

# aptitute install smbpasswd
try:
    import smbpasswd
    update_sambapassword = True
except ImportError,ie:
    #print "Could not find python-smbpasswd. Will only update general passwords,"
    #print "and not samba-passwords."
    update_sambapassword = False

###############################################################################################
#
# Configuration
#
###############################################################################################

debug = False
uri = 'ldap://127.0.0.1' # or whatever is the "cn" in the server's certificate
# Hardcode a simple proxy-user with minimal rights, or open for anonymous search if disabled.
# Basically, we need to search after a given users distinguished name (dn) in user_base.
binddn = 'cn=admin,dc=dmi,dc=dk' 
bindpw = 'Slover5755!'
user_base = 'ou=IT,dc=dmi,dc=dk' # Where can we find users in this tree?
filterattribute='uid'
# Support selfsigned certificates, unless this is enabled through /etc/ldap.conf (TLS_REQCERT allow)
#ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ???)

###############################################################################################
#
# Functions
#
###############################################################################################

def usage():
    """How to use this module
    """
    print "Debian-Edu Password-change utility."
    print ""
    print "To change your own password(s):"
    print "  %s" % (sys.argv[0])
    print ""
    print "To change a different persons' password(s):"
    print "  %s -u <username>" % (sys.argv[0])
    print ""
    print "This help:"
    print "  %s -h" % (sys.argv[0])
    print ""
    sys.exit()

def getsalt(chars = string.letters + string.digits,length=16):
    """Generate a random salt. Default length is 16.
       Originated from mkpasswd in Luma
    """
    salt = ""
    for i in range(int(length)):
        salt += random.choice(chars)
    return salt

def mkpasswd(pwd,hash='ssha'):
    """Generate hashed passwords. Originated from mkpasswd in Luma
    """
    alg = {
        'ssha':'Seeded SHA-1',
        'sha':'Secure Hash Algorithm',
        'smd5':'Seeded MD5',
        'md5':'MD5',
        'crypt':'Standard unix crypt'
    }
    # Don't add support for sambapasswords unless we're using it
    if (update_sambapassword):
        alg['lmhash'] = 'Lanman hash'
        alg['nthash'] = 'NT Hash'
    if hash not in alg.keys():
        return "Algorithm <%s> not supported in this version." % hash
    else:
        salt = getsalt()
        if hash == "ssha":
            return "{SSHA}" + base64.encodestring(sha.new(str(pwd) + salt).digest() + salt)
        elif hash == "sha":
            return "{SHA}" + base64.encodestring(sha.new(str(pwd)).digest())
        elif hash == "md5":
            return "{SHA}" + base64.encodestring(md5.new(str(pwd)).digest())
        elif hash == "smd5":
            return "{SMD%}" + base64.encodestring(md5.new(str(pwd) + salt).digest() + salt)
        elif hash == "crypt":
            return "{CRYPT}" + crypt.crypt(str(pwd),getsalt(length=2))
        # nt/lm-hash are used directly in their own password-attributes.. no need to prefix the hash
        elif hash == "lmhash":
            return smbpasswd.lmhash(pwd)
        elif hash == "nthash":
            return smbpasswd.nthash(pwd)


def get_dn(username):
    """Searches the LDAPtree for this username. Returns its dn.
    """
    dn = None
    try:
        l = ldap.initialize(uri)
    except LDAPError,le:
        print "Error connecting to ldapserver."
        print "Reason: %s" % (repr(le))
        sys.exit()
    filter = filterattribute + '=' + username
    if debug:
        print "SearchFilter: %s" % filter
    try:
        l.simple_bind_s('','')
        res = l.search_s(user_base,ldap.SCOPE_ONELEVEL,filter)
        try:
            dn = res[0][0] # res is a list of tuple objects, where the first element is dn, other is ldif
            if debug:
                print "Found dn: %s" % dn
        except IndexError,ie:
            print "User not found in database"
            sys.exit()
    except ldap.UNWILLING_TO_PERFORM,e:
        print "Server is unwilling to perform the operation."
        sys.exit()
    except ldap.LDAPError,le:
        print "An error occured while talking to the server: ", le
        sys.exit()
    return dn

def get_passwd():
    """Helper function to retrieve new password"""
    p1 = getpass('Enter new password: ')
    if (len(p1) < 6):
        print "Password length too short. Passwords are 6-8 characters"
        p1 = get_passwd()
    else:
        p2 = getpass('Retype new password: ')
        if (p1 != p2):
            print "Password mismatch."
            sys.exit()
    return p1

def do_change(username,debug):
    """Main function - handles ldap write operations.
    """
    binddn = get_dn(getuser())
    bindpw = getpass('(Your own) Password:')
    if debug:
        print "Binding as: %s" % binddn
    user = get_dn(username)
    if debug:
        print "Changing password for dn: %s" % user
    try:
        l = ldap.initialize(uri)
        l.simple_bind_s(binddn,bindpw)
    except ldap.INVALID_CREDENTIALS:
        print "Wrong username and/or password - or not enough encryption."
        sys.exit()
    except ldap.LDAPError,le:
        print "An error occured while connecting to LDAP server"
        print "Reason: %s" % (le.args)
        sys.exit()

    newPassword = get_passwd()
    ldif = []
    # We change password on attribute userPassword,sambaLMPassword and sambaNTPassword
    ldif.append((ldap.MOD_REPLACE,"userPassword",mkpasswd(newPassword,hash='md5')))
    # Perhaps set attributes such as sambaPwdLastSet,shadowExpire and shadowLastChange 
    # Are these attributes used with functionality anywhere?
    if update_sambapassword:
        ldif.append((ldap.MOD_REPLACE,"sambaLMPassword",mkpasswd(newPassword,hash='lmhash')))
        ldif.append((ldap.MOD_REPLACE,"sambaNTPassword",mkpasswd(newPassword,hash='nthash')))
    if debug:
        print "Modifying dn: %s" % (user)
        print "LDIF :\n %s" % (ldif)
    # Finally, we try to modify the object
    try:
        l.modify_s(user,ldif)
        print "Password(s) changed on user %s" % (username)
    except ldap.LDAPError,e:
        print "An error occured while modifying %s" % (username)
        print "Reason: %s" % (e.args)
        sys.exit()
        

if __name__ == '__main__':
    args = sys.argv[1:]
    if ('-u' in args):
        try:
            username = args[1]
        except:
            usage()
    elif ('-h' in args):
        usage()
    else:
        # If no username is supplied at commandline, assume current user wants
        # to change his/her password(s)
        username = getuser()
    if debug:
        print "Trying to change password for user: %s" % username
    do_change(username,debug)
