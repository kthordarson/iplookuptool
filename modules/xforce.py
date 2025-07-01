from loguru import logger
import os
import requests
# https://api.xforce.ibmcloud.com/doc/

# https://exchange.xforce.ibmcloud.com
# curl -X GET --header 'Accept: application/json' -u {API_KEY:API_PASSWORD} 'https://exchange.xforce.ibmcloud.com/api/url/foourl.com'

import hashlib
import base64

def get_xforce_data(apiurl, scanurl, headers):
	try:
		fullurl = apiurl + scanurl
		response = requests.get(fullurl, params='', headers=headers, timeout=20)
		logger.debug(f'X-Force response: {response.status_code} {response.text}')
		all_json = response.json()
		return all_json
	except Exception as e:
		logger.error(f'Error constructing URL: {e} {type(e)}')
		return None
	# json.dumps(all_json, indent=4, sort_keys=True)

def get_xforce_ipreport(ipaddr):
	try:
		token = get_token()
		headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
		url = f"https://api.xforce.ibmcloud.com:443/ipr/{ipaddr}"
		response = requests.get(url, params='', headers=headers, timeout=20)
		all_json = response.json()
		return all_json
	except Exception as e:
		logger.error(f'Error fetching X-Force IP report: {e} {type(e)}')
		return None
	# json.dumps(all_json, indent=4, sort_keys=True)

def get_md5(filename):
	try:
		f = open(filename,"rb")
		md5 = hashlib.md5((f).read()).hexdigest()
		return md5
	except Exception as e:
		logger.error(f'Error calculating MD5 for {filename}: {e} {type(e)}')

def get_token():
	try:
		xapikey = os.environ.get("XFORCEAPIKEY")
		xpass = os.environ.get("XFORCEAPIPASS")

		t = xapikey + ":" + xpass
		logger.debug(f'xforce token: {t}')
		token = base64.b64encode(t.encode('utf8'))
		return token.decode('utf8')
	except Exception as e:
		logger.error(f'missing xforce api key {e} {type(e)}')
		return None

if __name__ == "__main__":
	pass
