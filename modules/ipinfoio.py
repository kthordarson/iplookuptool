import os
import aiohttp
from loguru import logger

async def get_ipinfo(ipaddr):
	"""
	Query ipinfo.io API for IP geolocation info.

	Args:
		ipaddr (str): IP address to look up

	Returns:
		dict: Geolocation data or None if error
	"""
	api_key = os.environ.get("IPINFOIO_APIKEY")
	if not api_key:
		logger.warning("missing ipinfo.io api key")
		url = f"https://ipinfo.io/{ipaddr}/json"
	else:
		# todo add api key to the url
		url = f"https://ipinfo.io/{ipaddr}/json"
	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(url) as response:
				if response.status == 200:
					data = await response.json()
					return data
				else:
					logger.error(f"ipinfo error: {response.status} {response.reason} for {ipaddr}")
					return None
	except Exception as e:
		logger.error(f"ipinfo exception: {e} {type(e)} for {ipaddr}")
		return None
