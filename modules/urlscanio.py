import socket
import os
import sys
from loguru import logger
import requests



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
	response = requests.get(url, params=params, headers=headers, timeout=20)
	all_json = response.json()
	return all_json
