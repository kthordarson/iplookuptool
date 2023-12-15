import os
import sys
from loguru import logger

try:
	from ipwhois import IPWhois
	from ipwhois.exceptions import HostLookupError, HTTPLookupError
except ImportError as e:
	logger.error(f'missing ipwhois package')
	os._exit(-1)

def get_ipwhois(ipaddr):
	result = None
	try:
		obj = IPWhois(ipaddr)
		rdap = obj.lookup_rdap()
		result = f"{rdap['asn_description']};{rdap['network']['name']};{rdap['network']['cidr']};{rdap['network']['start_address']};{rdap['network']['end_address']}"
		return result
	except HTTPLookupError as e:
		logger.warning(f'[!] Error: {e} for address {ipaddr}')
	except ValueError as e:
		logger.warning(f'[!] error: {e} ipaddr: {ipaddr}')
	except Exception as e:
		logger.error(f'[!] Error: {e} {type(e)} for address {ipaddr}')
	finally:
		return result
