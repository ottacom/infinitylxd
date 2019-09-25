#!/usr/bin/python
import argparse
import sys
import os	
import json
import re
import lepl.apps.rfc3696
import requests
import progress
import time
import multiprocessing
import getpass
import re
from termcolor import colored , cprint

DELAY = 0.1
DISPLAY = [ '|', '/', '-', '\\' ]

def spinner_func(before='', after=''):
    write, flush = sys.stdout.write, sys.stdout.flush
    pos = -1
    while True:
        pos = (pos + 1) % len(DISPLAY)
        msg = before + DISPLAY[pos] + after
        write(msg); flush()
        write('\x08' * len(msg))
        time.sleep(DELAY)


class ilxd(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='Pretends to be ilxd',
            usage='''ilxd <command> [<args>]
The InfinitLXD commands are:

user
   Description: Manage the user acoount
   Syntax example: ilxd user -a signup -e myemail@myemail.com -u https://127.0.0.1:8000
   available actions: 
   	signup     
   	login
   	logout 
   	logoutall
   	recovery
   	changepwd

''')
        parser.add_argument('command', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print console_msg('0')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()



    def user(self):
        parser = argparse.ArgumentParser(description='Use this commmand to sign-up in the system')
	parser.add_argument('-a', '--action',required=True, help="""Actions available: signup,login,logout,recovery,destroy""")
	ilxdemail=get_ilxdemail()
	ilxdserverurl=get_ilxdserverurl() 
	if not ilxdserverurl :
		parser.add_argument('-u', '--ilxdserverurl',required=True, 
				   help="""Your server url ex: https://ilxdserv.mynet.coms:8000 you can also setup an enviroment variable ilxdserverurl=https://ilxdserv.mynet.coms:8000 """)
	
	else:

		parser.add_argument('-u', '--ilxdserverurl',required=False,
				   help="""Your server url ex: https://ilxdserv.mynet.coms:8000 you can also setup an enviroment variable ilxdserverurl=https://ilxdserv.mynet.coms:8000 """)

	if not ilxdemail :
                parser.add_argument('-e', '--ilxdemail',required=True, 
                                   help="""Please provide your email address , you can also setup an enviroment variable ilxdemail=my@example.com""")

        else:
		parser.add_argument('-e', '--ilxdemail',required=False, help="""Your email address to signup""")


        args = parser.parse_args(sys.argv[2:])
	
	if args.ilxdserverurl:

		 ilxdserverurl=args.ilxdserverurl
	if args.ilxdemail:
		ilxdemail=args.ilxdemail

	if email_validation(args.ilxdemail) == False:
		print console_msg('1')
        	quit()
        	sys.exit(1)
		
	else :
		if args.action == "signup":
			signup (args.ilxdemail,ilxdserverurl)
		if args.action == "login":
                        login (args.ilxdemail,ilxdserverurl)
		if args.action == "logout":
                        logout (args.ilxdemail,ilxdserverurl)
		if args.action == "logoutall":
                        logoutall (args.ilxdemail,ilxdserverurl)
		if args.action == "recovery":
                        recovery (args.ilxdemail,ilxdserverurl)
		if args.action == "changepwd":
                        changepwd (args.ilxdemail,ilxdserverurl)





    def fetch(self):
        parser = argparse.ArgumentParser(
            description='Download objects and refs from another repository')
        # NOT prefixing the argument with -- means it's not optional
        parser.add_argument('repository')
        args = parser.parse_args(sys.argv[2:])
        print 'Running ilxd fetch, repository=%s' % args.repository



def email_validation(email):
        email_validator = lepl.apps.rfc3696.Email()
        if not email_validator(email):
        	return False
	else: 
		return True

def get_ilxdserverurl():
	try:
		return os.environ['ilxdserverurl'] 
	
	except Exception, error:
                return ""
def get_ilxdemail():
        try:
                return os.environ['ilxdemail']

        except Exception, error:
                return ""

	
def loadresources():
    global messages
    try:
            with open('./resources/messages.json') as json_data:
                  messages = json.load(json_data)
    except Exception, e:
        print e
        print "Something is going wrong , please take a look on the resources directory"
        sys.exit(1)



def console_msg(cod):
#	return colored(json.dumps(messages[cod][0]["message"]).replace("\"",""),json.dumps(messages[cod][0]["color"].replace("\"","")))
	return colored(json.dumps(messages[cod][0]["message"]).replace("\"",""),json.dumps(messages[cod][0]["color"]).replace("\"",""))


def password_validation(password):
        if len(password) < 8:
	    print console_msg('3')
        elif re.search('[0-9]',password) is None:
	    print console_msg('4')
        elif re.search('[A-Z]',password) is None: 
	    print console_msg('5')
        elif re.search('[a-z]',password) is None: 
	    print console_msg('8')
	elif re.match(r'^\w+$',password):
	    print console_msg('9')
        else:
	    print console_msg('7')
	    return True

def send_request(action,ilxdemail,ilxdserverurl,password=None,oldpassword=None):
	spinner = multiprocessing.Process(
                None, spinner_func, args=('', ''))
        spinner.start()
	if not password:
       		 r = requests.post(ilxdserverurl+"/"+action, json={"ilxdemail": ""+ilxdemail+""}, verify=False)
	elif oldpassword:
		 r = requests.post(ilxdserverurl+"/"+action, json={"ilxdemail": ""+ilxdemail+"","password":""+password+"","oldpassword":""+oldpassword}, verify=False)
	elif password:
      		 r = requests.post(ilxdserverurl+"/"+action, json={"ilxdemail": ""+ilxdemail+"","password":""+password+""}, verify=False)
	while not r :
           spinner.terminate()

	if r.status_code != 200:
		print console_msg('415')+" "+ilxdserverurl+"as answered status code "+r.status_code
                quit()
                sys.exit(1)
        else:
            spinner.terminate()
            sys.stdout.write("\b")
            print console_msg(r.json())

def signup(ilxdemail,ilxdserverurl):

       #Ask for a password
       password = getpass.getpass(console_msg('10'))
       password2 = ""
       if password_validation(password) == True:
		password2 = getpass.getpass(console_msg('11'))
	        if password != password2:
			print  console_msg('6')
			signup(ilxdemail,ilxdserverurl)
       else:
		signup(ilxdemail,ilxdserverurl)
		quit()
                sys.exit(1)
       try:
	   send_request("signup",ilxdemail,ilxdserverurl,password)

       except Exception, error:
		print error
                print console_msg('500')



def changepwd(ilxdemail,ilxdserverurl):

       currentpassword = getpass.getpass(console_msg('13'))
       password = getpass.getpass(console_msg('10'))
       password2 = ""
       if password_validation(password) == True:
                password2 = getpass.getpass(console_msg('11'))
                if password != password2:
                        print  console_msg('6')
                        signup(ilxdemail,ilxdserverurl)
       else:
                changepwd(ilxdemail,ilxdserverurl)
                quit()
                sys.exit(1)
       try:
           send_request("changepwd",ilxdemail,ilxdserverurl,password,currentpassword)

       except Exception, error:
		print error
                print console_msg('500')


def login(ilxdemail,ilxdserverurl):
	password = getpass.getpass(console_msg('12'))
	try:
	   send_request("login",ilxdemail,ilxdserverurl,password)  
        except Exception, error:
                print console_msg('500')


def logout(ilxdemail,ilxdserverurl):
        try:
	   send_request("logout",ilxdemail,ilxdserverurl) 
        except Exception, error:
                print console_msg('500')


def logoutall(ilxdemail,ilxdserverurl):
        try:
	   send_request("logoutall",ilxdemail,ilxdserverurl)	
        except Exception, error:
                print console_msg('500')

def recovery(ilxdemail,ilxdserverurl):
        try:
           send_request("recovery",ilxdemail,ilxdserverurl)
        except Exception, error:
                print console_msg('500')


	
if __name__ == '__main__':
#THIS DISABLE WARINNGS ABOUT SELF SIGNED HTTPS
    requests.packages.urllib3.disable_warnings()
#
    loadresources()
    ilxd()
