from loguru import logger
from ipwhois.exceptions import IPDefinedError
try:
	from ipwhois import IPWhois
	from ipwhois.exceptions import HTTPLookupError
except ImportError as e:
	logger.error(f'missing ipwhois package {e}')
	# os._exit(-1)

def get_ipwhois(ipaddr):
	result = None
	try:
		obj = IPWhois(ipaddr)
		rdap = obj.lookup_rdap()
		result = f"{rdap['asn_description']};{rdap['network']['name']};{rdap['network']['cidr']};{rdap['network']['start_address']};{rdap['network']['end_address']}"
		return result
	except IPDefinedError as e:
		logger.warning(f'[!] Error: {e} for address {ipaddr}')
		raise e
	except HTTPLookupError as e:
		logger.warning(f'[!] Error: {e} for address {ipaddr}')
	except ValueError as e:
		logger.warning(f'[!] error: {e} ipaddr: {ipaddr}')
	except Exception as e:
		logger.error(f'[!] Error: {e} {type(e)} for address {ipaddr}')
	finally:
		return result
