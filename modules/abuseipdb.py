from loguru import logger
import os
import aiohttp

ABUSEIPDBAPIKEY = os.environ.get("ABUSEIPDBAPIKEY")
if not ABUSEIPDBAPIKEY:
	logger.error("missing abuseipdb api key")
	os._exit(-1)


async def get_abuseipdb_data(ipaddr, maxdays=30):
	# https://www.abuseipdb.com/api.html
	# https://www.abuseipdb.com/check/[IP]/json?key=[API_KEY]&days=[DAYS]
	headers = {"Key": ABUSEIPDBAPIKEY, "Accept": "application/json"}
	params = {
		"maxAgeInDays": maxdays,
		"ipAddress": ipaddr,
		"verbose": "True",
	}

	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(
				"https://api.abuseipdb.com/api/v2/check", headers=headers, params=params
			) as response:
				# response = requests.get(f'https://www.abuseipdb.com/check/{ipaddr}/json?key={ABUSEIPDBAPIKEY}&days={maxdays}&verbose', headers=headers, params=params)
				if response.status == 200:
					try:
						jsonresp = await response.json()
					except Exception as e:
						logger.error(f"[!] {e} {type(e)} while parsing json response")
						return None
					if jsonresp:
						data = jsonresp
						data["url"] = (
							f"https://www.abuseipdb.com/check/{ipaddr}/json?key={ABUSEIPDBAPIKEY}&days={maxdays}&verbose"
						)
						return data
					else:
						logger.error(
							f"Unknown error for {ipaddr} json: {jsonresp}"
						)
						return None
				else:
					logger.warning(f"[!] {response.status} {response.reason} for {ipaddr}")
					return None
	except Exception as e:
		logger.error(f"[!] {e} {type(e)}")
		return None
