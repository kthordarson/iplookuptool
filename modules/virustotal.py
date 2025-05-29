from loguru import logger
import os
import requests

VTAPIKEY = os.environ.get("VTAPIKEY")
if not VTAPIKEY:
	logger.error('missing virus total api key')
	os._exit(-1)

try:
	from vt import Client
	# from vt.error import APIError
except ImportError as e:
	logger.error(f'missing virustotal package {e} {type(e)}')
	os._exit(-1)

def get_virustotal_info(ipaddr):
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}"
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	try:
		response = requests.get(url, headers=headers)
	except Exception as e:
		logger.error(f'[!] {e} {type(e)} addr: {ipaddr}')
		return None
	#  [resptext['data']['attributes']['last_analysis_results'][k] for k in resptext['data']['attributes']['last_analysis_results']]
	# results = response.text['data']['attributes']['last_analysis_stats']
	jsonresults = response.json()
	# results['data']['attributes']['last_analysis_stats']
	return jsonresults['data']['attributes']  # ['last_analysis_stats']

def get_virustotal_comments(ipaddr, limit=10):
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}/comments?limit={limit}"
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	response = requests.get(url, headers=headers)
	jsonresults = response.json()
	return jsonresults  # ['data']['attributes']

def get_virustotal_scanurls(url):
	payload = {"url": url}
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY, "content-type": "application/x-www-form-urlencoded"}
	url = "https://www.virustotal.com/api/v3/urls"
	# headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	# response = requests.get(url, headers=headers)
	response = requests.post(url, data=payload, headers=headers)
	data0 = response.json()
	infourl = data0.get('data').get('links').get('self')
	return infourl  # ['data']['attributes']

def get_virustotal_urlinfo(vturl):
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	response = requests.get(vturl, headers=headers)
	data0 = response.json()
	return data0  # ['data']['attributes']

def get_virustotal_objects(ipaddr, limit=10, relation='comments'):
	# Relationship	Description	Accessibility	Return object type
	# comments	Comments for the IP address.	Everyone.	List of Comments.
	# communicating_files	Files that communicate with the IP address.	Everyone.	List of Files.
	# downloaded_files	Files downloaded from the IP address.	VT Enterprise users only.	List of Files.
	# graphs	Graphs including the IP address.	Everyone.	List of Graphs.
	# historical_ssl_certificates	SSL certificates associated with the IP.	Everyone.	List of SSL Certificate.
	# historical_whois	WHOIS information for the IP address.	Everyone.	List of Whois.
	# related_comments	Community posted comments in the IP's related objects.	Everyone.	List of Comments.
	# related_references	References related to the IP address.	VT Enterprise users only.	List of References.
	# related_threat_actors	Threat actors related to the IP address.	VT Enterprise users only.	List of Threat Actors.
	# referrer_files	Files containing the IP address.	Everyone.	List of Files.
	# resolutions	IP address' resolutions	Everyone.	List of Resolutions.
	# urls	URLs related to the IP address.	VT Enterprise users only.	List of URLs.
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}/{relation}?limit={limit}"
	# url = f"https://www.virustotal.com/api/v3/ip_addresses/173.233.137.44/comments?limit=10"
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	response = requests.get(url, headers=headers)
	jsonresults = response.json()
	return jsonresults  # ['data']['attributes']

def get_vt_ipinfo(ipaddr):
	vtipinfo = None
	try:
		client = Client(VTAPIKEY)
	except Exception as e:
		logger.error(f'[!] {e} {type(e)} addr: {ipaddr}')
		return None
	try:
		vtipinfo = client.get_object(f'/ip_addresses/{ipaddr}')
	# except APIError as e:
	# 	logger.warning(f'[!] {e} {type(e)} addr: {ipaddr}')
	except Exception as e:
		logger.error(f'[!] unhandled {e} {type(e)} addr: {ipaddr}')
		return None
	client.close()
	return vtipinfo

def do_vt_search(ipaddr, limit=10):
	with Client(VTAPIKEY) as client:
		it = client.iterator("/intelligence/search", params={"query": ipaddr}, limit=limit)
		for obj in it:
			print(f"{obj.type}:{obj.id}")

