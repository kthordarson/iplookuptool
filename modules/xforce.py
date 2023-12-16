from loguru import logger
import os
import requests
import json
# https://api.xforce.ibmcloud.com/doc/

# Lance Mueller
# July 21, 2016

import requests
import sys
import json
from optparse import OptionParser
import hashlib
import base64

def get_xforce_data(apiurl, scanurl, headers):
	fullurl = apiurl +  scanurl
	response = requests.get(fullurl, params='', headers=headers, timeout=20)
	all_json = response.json()
	return all_json
	# json.dumps(all_json, indent=4, sort_keys=True)

def get_xforce_ipreport(ipaddr):
	token = get_token()
	headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
	url = f"https://api.xforce.ibmcloud.com:443/ipr/{ipaddr}"
	response = requests.get(url, params='', headers=headers, timeout=20)
	all_json = response.json()
	return all_json
	# json.dumps(all_json, indent=4, sort_keys=True)

def get_md5(filename):
	try:
		f = open(filename,"rb")
		md5 = hashlib.md5((f).read()).hexdigest()
		return md5
	except Exception as e:
		print(e)

def get_token():
	XFORCEAPIKEY = os.environ.get("XFORCEAPIKEY")
	XFORCEAPIPASS = os.environ.get("XFORCEAPIPASS")

	t = XFORCEAPIKEY + ":" + XFORCEAPIPASS
	token = base64.b64encode(t.encode('utf8'))
	return token.decode('utf8')

if __name__ == "__main__":
	pass