import os
import requests
# https://api.xforce.ibmcloud.com/doc/

# https://exchange.xforce.ibmcloud.com
# curl -X GET --header 'Accept: application/json' -u {API_KEY:API_PASSWORD} 'https://exchange.xforce.ibmcloud.com/api/url/foourl.com'

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