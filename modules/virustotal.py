from loguru import logger
import os
import aiohttp

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

async def get_virustotal_info(ipaddr):
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}"
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(url, headers=headers) as response:
				jsonresults = await response.json()
				return jsonresults['data']['attributes']
	except Exception as e:
		logger.error(f'[!] {e} {type(e)} addr: {ipaddr}')
		return None

async def get_virustotal_comments(ipaddr, limit=10):
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}/comments?limit={limit}"
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	async with aiohttp.ClientSession() as session:
		async with session.get(url, headers=headers) as response:
			jsonresults = await response.json()
			return jsonresults

async def get_virustotal_scanurls(url):
	payload = {"url": url}
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY, "content-type": "application/x-www-form-urlencoded"}
	request_url = "https://www.virustotal.com/api/v3/urls"
	async with aiohttp.ClientSession() as session:
		async with session.post(request_url, data=payload, headers=headers) as response:
			data0 = await response.json()
			infourl = data0.get('data').get('links').get('self')
			return infourl

async def get_virustotal_urlinfo(vturl):
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	async with aiohttp.ClientSession() as session:
		async with session.get(vturl, headers=headers) as response:
			data0 = await response.json()
			return data0

async def get_virustotal_objects(ipaddr, limit=10, relation='comments'):
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
	async with aiohttp.ClientSession() as session:
		async with session.get(url, headers=headers) as response:
			jsonresults = await response.json()
			return jsonresults

async def get_vt_ipinfo(args):
	vtipinfo = {}
	try:
		async with Client(VTAPIKEY) as client:
			vtipinfo = await client.get_object_async(f'/ip_addresses/{args.host}')
	except Exception as e:
		logger.error(f'[!] unhandled {e} {type(e)} addr: {args.host}')
	finally:
		return vtipinfo

async def do_vt_search(ipaddr, limit=10):
	async with Client(VTAPIKEY) as client:
		async for obj in client.iterator_async("/intelligence/search", params={"query": ipaddr}, limit=limit):  # type: ignore
			print(f"{obj.type}:{obj.id}")

