import os
from urllib3.exceptions import MaxRetryError
from opensearchpy import OpenSearch
from loguru import logger
# from myglapi.apis.searchuniversalrelative_api import SearchuniversalrelativeApi
# from myglapi.rest import ApiException
# from myglapi import rest
GRAYLOGAPIKEY = os.environ.get('GRAYLOGAPIKEY')
def graylog_search_ip(ip_address, range=86400):
	# search = SearchuniversalrelativeApi()
	# client = OpenSearch(hosts=os.environ.get('GRAYLOG_HOST'), use_ssl=False, verify_certs=False, http_auth=(os.environ.get('GRAYLOG_USER'),os.environ.get('GRAYLOG_PASS')))
	# ipaddr = args.host  # '31.209.157.27'
	query = {'size': 5,'query': {'multi_match': {'query': ip_address,'fields': ['srcip', 'dstip', 'remip']}}}
	client = OpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False)
	# q='RemoteMGNT'
	# range=(86400)
	res = None
	try:
		res = client.search(body=query, size=1000)
	except Exception as e:
		logger.error(f'graylog search error: {e} {type(e)}')
		raise e
	# logger.debug(f'[s] searchres: {res} q={query} range={range}')
	return res

def graylog_search(query, range=86400):
	# search = SearchuniversalrelativeApi()
	# client = OpenSearch(hosts=os.environ.get('GRAYLOG_HOST'), use_ssl=False, verify_certs=False, http_auth=(os.environ.get('GRAYLOG_USER'),os.environ.get('GRAYLOG_PASS')))
	# ipaddr = args.host  # '31.209.157.27'
	query = {'size': 5,'query': {'multi': {'query': query}}}  # ,'fields': ['srcip', 'dstip']}}}
	client = OpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False)
	# q='RemoteMGNT'
	# range=(86400)
	res = None
	try:
		res = client.search(body=query, size=1000)
	except Exception as e:
		logger.error(f'graylog search error: {e} {type(e)}')
		raise e
	# logger.debug(f'[s] searchres: {res} q={query} range={range}')
	return res

if __name__ == '__main__':
	pass
