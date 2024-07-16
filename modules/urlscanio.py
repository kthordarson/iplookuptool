import os
from loguru import logger
import requests

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.SSLError)

def get_urlscanio_data(ipaddr):
	# https://urlscan.io/docs/api/
	pass

def search_urlscanio(remoteurl):
	URLSCANIOAPIKEY = os.environ.get("URLSCANIOAPIKEY")
	headers = {
		'Authorization': 'Basic',
		'API-Key': URLSCANIOAPIKEY}
	params = {
		'q': remoteurl,
			}
	url = 'https://urlscan.io/api/v1/search/'
	try:
		response = requests.get(url, params=params, headers=headers, timeout=20, verify=False)
	except requests.exceptions.Timeout as e:
		logger.error(f"{e} for {url} {remoteurl}")
		return None
	except requests.exceptions.SSLError as e:
		logger.error(f"{e} {url} {remoteurl}")
		return None
	try:
		all_json = response.json()
	except Exception as e:
		logger.error(f"{e} {url} {remoteurl} response: {response.text}")
		return None
	return all_json
