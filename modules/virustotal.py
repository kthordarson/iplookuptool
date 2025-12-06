from loguru import logger
import os
import aiohttp

VTAPIKEY = os.environ.get("VTAPIKEY",'')
if not VTAPIKEY:
	logger.error('missing virus total api key')
	os._exit(-1)

try:
	from vt import Client
	# from vt.error import APIError
except ImportError as e:
	logger.error(f'missing virustotal package {e} {type(e)}')
	os._exit(-1)

async def get_virustotal_info(args):
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{args.ip}"
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(url, headers=headers) as response:
				jsonresults = await response.json()
				return jsonresults['data']['attributes']
	except Exception as e:
		logger.error(f'[!] {e} {type(e)} addr: {args.ip}')
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
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}/{relation}?limit={limit}"
	headers = {"accept": "application/json", "x-apikey": VTAPIKEY}
	async with aiohttp.ClientSession() as session:
		async with session.get(url, headers=headers) as response:
			jsonresults = await response.json()
			return jsonresults

async def get_vt_ipinfo(args):
	vtipinfo = {}
	try:
		async with Client(VTAPIKEY) as client:
			vtipinfo = await client.get_object_async(f'/ip_addresses/{args.ip}')
	except Exception as e:
		logger.error(f'[!] unhandled {e} {type(e)} addr: {args.ip}')
	return vtipinfo

async def do_vt_search(ipaddr, limit=10):
	async with Client(VTAPIKEY) as client:
		async for obj in client.iterator_async("/intelligence/search", params={"query": ipaddr}, limit=limit):  # type: ignore
			print(f"{obj.type}:{obj.id}")

