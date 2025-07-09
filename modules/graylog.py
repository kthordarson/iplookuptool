import os
from opensearchpy import AsyncOpenSearch
from loguru import logger
import urllib3
urllib3.disable_warnings()

GRAYLOGAPIKEY = os.environ.get('GRAYLOGAPIKEY')
async def graylog_search_ip(ip_address, range=86400):
	# search = SearchuniversalrelativeApi()
	# client = OpenSearch(hosts=os.environ.get('GRAYLOG_HOST'), use_ssl=False, verify_certs=False, http_auth=(os.environ.get('GRAYLOG_USER'),os.environ.get('GRAYLOG_PASS')))
	# ipaddr = args.host  # '31.209.157.27'
	# query = {'size': 50,'query': {'multi_match': {'query': ip_address,'fields': ['srcip', 'dstip', 'remip', 'IpAddress']}}}
	query = {'query': {'multi_match': {'query': ip_address,'fields': ['srcip', 'dstip', 'remip', 'IpAddress', 'src', 'dst', 'ClientIP','VserverServiceIP','NatIPaddress','SourceAddress','VserverAddress']}}}
	res = None
	async with AsyncOpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False, ssl_show_warn=False) as client:
		# q='RemoteMGNT'
		# range=(86400)
		try:
			res = await client.search(body=query, size=10000)
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			raise e
		# logger.debug(f'[s] searchres: {res} q={query} range={range}')
		finally:
			await client.close()
			return res

async def graylog_search(query, range=86400):
	# search = SearchuniversalrelativeApi()
	# client = OpenSearch(hosts=os.environ.get('GRAYLOG_HOST'), use_ssl=False, verify_certs=False, http_auth=(os.environ.get('GRAYLOG_USER'),os.environ.get('GRAYLOG_PASS')))
	# ipaddr = args.host  # '31.209.157.27'
	query = {'size': 5,'query': {'multi': {'query': query}}}  # ,'fields': ['srcip', 'dstip']}}}
	
	async with AsyncOpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False, ssl_show_warn=False) as client:
		# q='RemoteMGNT'
		# range=(86400)
		try:
			res = await client.search(body=query, size=1000)
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			raise e
		# logger.debug(f'[s] searchres: {res} q={query} range={range}')
		return res

if __name__ == '__main__':
	pass
