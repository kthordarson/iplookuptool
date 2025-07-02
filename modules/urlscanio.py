import os
from loguru import logger
import aiohttp
import asyncio

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.SSLError)

async def get_urlscanio_data(ipaddr):
	# https://urlscan.io/docs/api/
	pass

async def search_urlscanio(remoteurl):
	urlscanapikey = os.environ.get("URLSCANIOAPIKEY")
	headers = {
		'Authorization': 'Basic',
		'API-Key': urlscanapikey}
	params = {
		'q': remoteurl,
			}
	url = 'https://urlscan.io/api/v1/search/'

	try:
		# Create SSL context that doesn't verify certificates (equivalent to verify=False)
		ssl_context = aiohttp.TCPConnector(ssl=False)
		timeout = aiohttp.ClientTimeout(total=20)

		async with aiohttp.ClientSession(connector=ssl_context, timeout=timeout) as session:
			async with session.get(url, params=params, headers=headers) as response:
				try:
					all_json = await response.json()
					return all_json
				except Exception as e:
					response_text = await response.text()
					logger.error(f"{e} {url} {remoteurl} response: {response_text}")
					return None
	except asyncio.TimeoutError as e:
		logger.error(f"{e} for {url} {remoteurl}")
		return None
	except aiohttp.ClientSSLError as e:
		logger.error(f"{e} {url} {remoteurl}")
		return None
	except aiohttp.ClientError as e:
		logger.error(f"{e} {url} {remoteurl}")
		return None
	except Exception as e:
		logger.error(f"Unexpected error: {e} {url} {remoteurl}")
		return None
