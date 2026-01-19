from loguru import logger
import os
import aiohttp

VIEWDNSAPIKEY = os.environ.get("VIEWDNSAPIKEY")

async def get_iphistory(domain, output='json'):
	# https://viewdns.info/api/ip-history/

	if not VIEWDNSAPIKEY:
		logger.warning("missing viewdns api key")
		return None

	api_url = f'https://api.viewdns.info/iphistory/?domain={domain}&apikey={VIEWDNSAPIKEY}&output={output}'

	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(api_url) as response:
				if response.status == 200:
					try:
						jsonresp = await response.json()
					except Exception as e:
						logger.error(f"[!] {e} {type(e)} while parsing json response")
						return None
					if jsonresp:
						return jsonresp
				else:
					logger.warning(f"[!] {response.status} {response.reason} for {domain}")
					return None
	except Exception as e:
		logger.error(f"[!] {e} {type(e)}")
		return None

async def get_subdomains(domain, output='json'):

	if not VIEWDNSAPIKEY:
		logger.warning("missing viewdns api key")
		return None

	api_url = f'https://api.viewdns.info/subdomains/?domain={domain}&apikey={VIEWDNSAPIKEY}&output={output}'

	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(api_url) as response:
				if response.status == 200:
					try:
						jsonresp = await response.json()
					except Exception as e:
						logger.error(f"[!] {e} {type(e)} while parsing json response")
						return None
					if jsonresp:
						return jsonresp
				else:
					logger.warning(f"[!] {response.status} {response.reason} for {domain}")
					return None
	except Exception as e:
		logger.error(f"[!] {e} {type(e)}")
		return None
