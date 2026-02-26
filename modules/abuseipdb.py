from loguru import logger
import os
import aiohttp

ABUSEIPDBAPIKEY = os.environ.get("ABUSEIPDBAPIKEY")

async def get_abuseipdb_data(args, maxdays=30):
	# https://www.abuseipdb.com/api.html
	# https://www.abuseipdb.com/check/[IP]/json?key=[API_KEY]&days=[DAYS]
	if not ABUSEIPDBAPIKEY:
		logger.warning("missing abuseipdb api key")
		return None
	headers = {"Key": ABUSEIPDBAPIKEY, "Accept": "application/json"}
	params = {
		"maxAgeInDays": maxdays,
		"ipAddress": args.ip,
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
							f"https://www.abuseipdb.com/check/{args.ip}/json?key={ABUSEIPDBAPIKEY}&days={maxdays}&verbose"
						)
						return data
					else:
						logger.error(
							f"Unknown error for {args.ip} json: {jsonresp}"
						)
						return None
				else:
					logger.warning(f"[!] {response.status} {response.reason} for {args.ip}")
					return None
	except Exception as e:
		logger.error(f"[!] {e} {type(e)}")
		return None
