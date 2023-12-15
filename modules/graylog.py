import os
import sys
from loguru import logger
GRAYLOGAPIKEY = os.environ.get('GRAYLOGAPIKEY')

from myglapi.apis.apidocs_api import ApiClient
from myglapi.apis.systeminputs_api import SysteminputsApi
from myglapi.apis.searchuniversalrelative_api import SearchuniversalrelativeApi
from myglapi.apis.streams_api import StreamsApi


def graylog_search(query, range=86400):
	search = SearchuniversalrelativeApi()
	# q='RemoteMGNT'
	# range=(86400)
	res = search.search_relative(query, range)
	# logger.info(f'[s] searchres: {res.total_results} q={query} range={range}')
	return res

if __name__ == '__main__':
	pass
