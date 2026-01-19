import os
import aiohttp
from loguru import logger

async def get_ip2loc_data(args):
	"""
	Query ip2location.io API for IP geolocation info.

	Args:
		ipaddr (str): IP address to look up

	Returns:
		dict: Geolocation data or None if error
	"""
	api_key = os.environ.get("IP2LOCATION_APIKEY")
	if not api_key:
		logger.warning("missing ip2location.io api key")
		url = f"https://api.ip2location.io/?ip={args.ip}&format=json"
	else:
		url = f"https://api.ip2location.io/?key={api_key}&ip={args.ip}&format=json"
	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(url) as response:
				if response.status == 200:
					data = await response.json()
					return data
				else:
					logger.error(f"ip2loc error: {response.status} {response.reason} for {args.ip}")
					return None
	except Exception as e:
		logger.error(f"ip2loc exception: {e} {type(e)} for {args.ip}")
		return None
