import json
import sys

def load_all():

#    try:
	
	    with open('./resources/info.json') as json_data:
 		  info = json.load(json_data)
	    with open('./resources/alert.json') as json_data:
                  alert = json.load(json_data) 
            with open('./resources/critical.json') as json_data:
                  critical = json.load(json_data)

#    except Exception, e:
#        print e
#        print "Something is going wrong , please take a look on the resources directory"
#        sys.exit(1)


