#!/usr/bin/python
import flask
from flask import Flask, request ,json , abort
from flask_restful import Resource, Api
from lib import loadconfig
from lib import generatepwd
from ldap3 import Server, Connection, ALL,MODIFY_REPLACE
import re
import os
import sha 
import time
import glob
import smtplib
from base64 import b64encode 
app = Flask(__name__)
api = Api(app)
todos = {}
data = {}

#Load configuration settings
loadconfig.load_configuration()



#Native functions
def domain_security_check (domain):
	if str(loadconfig.trusted_domains) == 'ALL':
		return True
	else:
		if str(domain) in str(loadconfig.trusted_domains):
			return True
		else:
			return False

def login_security_check(ip,mail):
	jdomain=mail.split('@')[-1]
	if domain_security_check(jdomain) == True:
	        if os.path.isfile('./active_session/user_'+ip+'_.'+mail) == True:
       		         return True
       		else:
               		 return False
	else:
		return False


def ldap_search(s_objectclass,s_pattern,s_attribute,s_pagedsize):
        try:
                server = Server(loadconfig.ldap_server(), get_info=ALL)
                conn = Connection(server , loadconfig.ldap_username(), loadconfig.ldap_password(), auto_bind=True)
		conn.search(search_base = loadconfig.ldap_search(),
                                 search_filter = '(&(objectclass='+s_objectclass+')('+s_pattern+'))',
                                 attributes = [ s_attribute[0],s_attribute[1] ],
                                 paged_size = s_pagedsize)
		conn.response=str(conn.response)
		if conn.response == "[]":
			return "404"
		else:
			#return json.dumps(str(conn.response).replace("'","\""))
                        #conn.response = str(conn.response)[2:-1]
                        conn.response=conn.response.replace("u'","'")
                        conn.response=conn.response.replace("'","\"")
                        return json.loads(conn.response)

        except Exception, error:
                 print error


def check_request_type (headers):
	if headers == 'text/plain':
                 #return "Text Message: " + request.data
                 return "T" 

        elif headers == 'application/json':
                 #return "JSON Message: " + json.dumps(request.json)
                 return "J"

        elif headers == 'application/octet-stream':
                 #f = open('./binary', 'wb')
                 #f.write(request.data)
                 #f.close()
                 return "B"

        else:
                 #return "415 Unsupported Media Type ;)"
                 return "415"


def password_validation(password):
        if len(password) < 8:
            return False
        elif re.search('[0-9]',password) is None:
            return False
        elif re.search('[A-Z]',password) is None:
            return False
        elif re.search('[a-z]',password) is None:
            return False
        elif re.match(r'^\w+$',password):
            return False
        else:
            return True


def hashPassword(password): 
    hash_object = hashlib.sha1(password)
    hex_dig = hash_object.hexdigest()
    return "{SHA}" +hex_dig


def open_session(ip,mail):
	if os.path.isfile('./active_session/user_'+ip+'_.'+mail) == True:
		return "exist"
	else:
   		sessionfile = open('./active_session/user_'+ip+'_.'+mail, 'w')
    		now=time.strftime("%Y-%m-%d %H:%M:%S")
    		sessionfile.write(now)
    		sessionfile.close()
		return "created"

def close_session(ip,mail):
	os.remove('./active_session/user_'+ip+'_.'+mail)
        if os.path.isfile('./active_session/user_'+ip+'_.'+mail) == True:
                return False
        else:
                return True


def close_all_session(ip,mail):
	for item in os.listdir("./active_session/"):
		if item.endswith("."+mail):
        		os.remove(os.path.join("./active_session/", item))
	#Verify
        if os.path.isfile('./active_session/user_'+ip+'_.'+mail) == True:
                return False
        else:
                return True

def send_recovery_mail(ip,mail,newpassword):
	sender = loadconfig.smtpsender
	#receivers = [mail]
	receivers = ["root@localhost"]
	subject = "Infinitylxd - Self generated email to recover your password"
	body = "This is automatic email to recover your password.\nYour new password is : "+newpassword+"\n"
	body = body + "Please consider to change your password as soon as possible\n"
	body = body + "Thanks,\nInfinitylxd Team\n"
	body = 'Subject: {}\n\n{}'.format(subject,body)


	try:
	   smtpObj = smtplib.SMTP(loadconfig.smtpserver)
	   smtpObj.sendmail(sender, receivers, body)         
	   return True
	except :
	   return False


@app.route('/signup', methods = ['POST'])
def api_signup():
	if (check_request_type(request.headers['Content-Type']) == "J"):

		jmail=json.loads(json.dumps(request.json))['ilxdemail']
                jdomain=jmail.split('@')[-1]
		jdc=jdomain.split('.')[0]
		jdc1=jdomain.split('.')[1]
		jpassword=json.loads(json.dumps(request.json))['password']
		
		#print jmail,loadconfig.ldap_gid_name(),jo,loadconfig.ldap_gid_name()
		if domain_security_check(jdomain) == True:

			response=ldap_search('inetOrgPerson','mail='+jmail,['mail','mail'],1)
			if password_validation(jpassword) == False:
				#password policy has ben violated by the client
				return json.dumps("403")
			if response == "404":
				#Adding group and user
				server = Server(loadconfig.ldap_server(), get_info=ALL)
		                conn = Connection(server , loadconfig.ldap_username(), loadconfig.ldap_password(), auto_bind=True)
				ctx = sha.new(jpassword) 
				jpassword = "{SHA}" + b64encode(ctx.digest())
				conn.add('ou='+loadconfig.ldap_gid_name()+','+loadconfig.ldap_search(), 'organizationalUnit')
				conn.add("cn="+jmail+",ou="+loadconfig.ldap_gid_name()+",dc="+jdc+",dc="+jdc1,'inetOrgPerson',{'sn': jmail,'mail': jmail,'uid': jmail, 'userpassword':jpassword})
				return json.dumps("201")

			else :
				 email_returned=json.dumps(response[0]["attributes"]["mail"])[2:-2]
				 if jmail == email_returned:
			 	 	return json.dumps("409")
		else :


	    	    return json.dumps("403")
	else:
		return json.dumps("415")




@app.route('/login', methods = ['POST'])
def api_login():
        if (check_request_type(request.headers['Content-Type']) == "J"):

                jmail=json.loads(json.dumps(request.json))['ilxdemail']
                jdomain=jmail.split('@')[-1]
                jdc=jdomain.split('.')[0]
                jdc1=jdomain.split('.')[1]
                jpassword=json.loads(json.dumps(request.json))['password']

                if domain_security_check(jdomain) == True:

                        if password_validation(jpassword) == False:
                                #password policy has ben violated by the client
                                return json.dumps("403")
			else:
				#print jpassword
				try:
		                	server = Server(loadconfig.ldap_server(), get_info=ALL)
               				#print(server ,"cn="+jmail+",ou="+loadconfig.ldap_gid_name()+","+loadconfig.ldap_search(), jpassword)
               				conn = Connection(server ,"cn="+jmail+",ou="+loadconfig.ldap_gid_name()+","+loadconfig.ldap_search(), jpassword, auto_bind=True)
					#open session
					clientip = request.remote_addr
					if (open_session(clientip,jmail)) == "created":
				
						return json.dumps("202")
					else:
						return json.dumps("202-1")
	 			except Exception, error:
					return json.dumps("403")

                else :


                    return json.dumps("403")
        else:
                return json.dumps("415")







@app.route('/logout', methods = ['POST'])
def api_logout():
        if (check_request_type(request.headers['Content-Type']) == "J"):

                jmail=json.loads(json.dumps(request.json))['ilxdemail']
                jdomain=jmail.split('@')[-1]
                clientip = request.remote_addr
                #print jmail,loadconfig.ldap_gid_name(),jo,loadconfig.ldap_gid_name()
                if login_security_check(clientip,jmail) == True:

                                #print jpassword
                                try:
                                        if (close_session(clientip,jmail)) == True:

                                                return json.dumps("202-2")
                                        else:
                                                return json.dumps("500")
                                except Exception, error:
                                        return json.dumps("403")

                else :


                    return json.dumps("403")
        else:
                return json.dumps("415")





@app.route('/logoutall', methods = ['POST'])
def api_logoutall():
        if (check_request_type(request.headers['Content-Type']) == "J"):

                jmail=json.loads(json.dumps(request.json))['ilxdemail']
                jdomain=jmail.split('@')[-1]
                clientip = request.remote_addr
                #print jmail,loadconfig.ldap_gid_name(),jo,loadconfig.ldap_gid_name()
                if login_security_check(clientip,jmail) == True:

                                #print jpassword
                                try:
                                        if (close_all_session(clientip,jmail)) == True:

                                                return json.dumps("202-3")
                                        else:
                                                return json.dumps("500")
                                except Exception, error:
                                        return json.dumps("403")

                else :


                    return json.dumps("403")
        else:
                return json.dumps("415")


@app.route('/recovery', methods = ['POST'])
def api_recovery():
        if (check_request_type(request.headers['Content-Type']) == "J"):

                jmail=json.loads(json.dumps(request.json))['ilxdemail']
                jdomain=jmail.split('@')[-1]
                jdc=jdomain.split('.')[0]
                jdc1=jdomain.split('.')[1]	
                clientip = request.remote_addr
                #print jmail,loadconfig.ldap_gid_name(),jo,loadconfig.ldap_gid_name()
                if domain_security_check(jdomain) == True:
				
                                #print jpassword
				newpassword=generatepwd.generate_pass()
                                try:
					#Modifying password
	                                server = Server(loadconfig.ldap_server(), get_info=ALL)
        	                        conn = Connection(server , loadconfig.ldap_username(), loadconfig.ldap_password(), auto_bind=True)
                	                ctx = sha.new(newpassword)
                        	        cryptnewpassword  = "{SHA}" + b64encode(ctx.digest())
                               		conn.modify("cn="+jmail+",ou="+loadconfig.ldap_gid_name()+",dc="+jdc+",dc="+jdc1,{'userpassword': [(MODIFY_REPLACE, [cryptnewpassword])]})
					#Sending  email
					if send_recovery_mail(clientip,jmail,newpassword) == True:
						return json.dumps("202-4")
					else:
						return json.dumps("500")
                                except Exception, error:
					print error
                                        return json.dumps("500")

                else :


                    return json.dumps("403")
        else:
                return json.dumps("415")



@app.route('/changepwd', methods = ['POST'])
def api_changepwd():
        if (check_request_type(request.headers['Content-Type']) == "J"):

                jmail=json.loads(json.dumps(request.json))['ilxdemail']
		jpassword=json.loads(json.dumps(request.json))['password']
		joldpassword=json.loads(json.dumps(request.json))['oldpassword']
                jdomain=jmail.split('@')[-1]
                jdc=jdomain.split('.')[0]
                jdc1=jdomain.split('.')[1]
                clientip = request.remote_addr
		if domain_security_check(jdomain) == True:

                        if password_validation(jpassword) == False:
                                #password policy has ben violated by the client
                                return json.dumps("403")
                        else:
                                #print jpassword
                                try:
                                        server = Server(loadconfig.ldap_server(), get_info=ALL)
                                        print(server ,"cn="+jmail+",ou="+loadconfig.ldap_gid_name()+","+loadconfig.ldap_search(),joldpassword, jpassword)
                                        conn = Connection(server ,"cn="+jmail+",ou="+loadconfig.ldap_gid_name()+","+loadconfig.ldap_search(), joldpassword, auto_bind=True)
                                        #Change password - connecting by superuser
					conn = Connection(server , loadconfig.ldap_username(), loadconfig.ldap_password(), auto_bind=True)	
                                        ctx = sha.new(jpassword)
                                        cryptnewpassword  = "{SHA}" + b64encode(ctx.digest())
                                        conn.modify("cn="+jmail+",ou="+loadconfig.ldap_gid_name()+",dc="+jdc+",dc="+jdc1,{'userpassword': [(MODIFY_REPLACE, [cryptnewpassword])]})
                                        return json.dumps("202-5")
                                except Exception, error:
					print error
                                        return json.dumps("403")


                else :


                    return json.dumps("403")
        else:
                return json.dumps("415")

