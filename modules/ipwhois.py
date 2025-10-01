from loguru import logger
from ipwhois.exceptions import IPDefinedError
from ipwhois import IPWhois
from ipwhois.exceptions import HTTPLookupError

import asyncio

async def get_ipwhois(args):
	result = None
	try:
		def _sync_lookup():
			obj = IPWhois(args.ipaddress)
			rdap = obj.lookup_rdap()
			return f"{rdap['asn_description']};{rdap['network']['name']};{rdap['network']['cidr']};{rdap['network']['start_address']};{rdap['network']['end_address']}"  # type: ignore

		# Run the synchronous operation in a thread pool
		result = await asyncio.to_thread(_sync_lookup)
		return result
	except IPDefinedError as e:
		logger.warning(f'[!] Error: {e} for address {args.ipaddress}')
		raise e
	except HTTPLookupError as e:
		logger.warning(f'[!] Error: {e} for address {args.ipaddress}')
		return result
	except ValueError as e:
		logger.warning(f'[!] error: {e} ipaddr: {args.ipaddress}')
		return result
	except Exception as e:
		logger.error(f'[!] Error: {e} {type(e)} for address {args.ipaddress}')
		return result
