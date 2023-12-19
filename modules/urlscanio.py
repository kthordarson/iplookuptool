import socket
import os
import sys
from loguru import logger
import requests

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
	url = f'https://urlscan.io/api/v1/search/'
	try:
		response = requests.get(url, params=params, headers=headers, timeout=20, verify=False)
	except requests.exceptions.Timeout as e:
		logger.error(f"{e} for {url} {remoteurl}")
		return None
	except requests.exceptions.SSLError as e:
		logger.error(f"{e} {url} {remoteurl}")
		return None
	all_json = response.json()
	return all_json
