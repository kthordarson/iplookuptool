import os
import sys
from loguru import logger
GRAYLOGAPIKEY = os.environ.get('GRAYLOGAPIKEY')

from myglapi.apis.apidocs_api import ApiClient
from myglapi.apis.systeminputs_api import SysteminputsApi
from myglapi.apis.searchuniversalrelative_api import SearchuniversalrelativeApi
from myglapi.apis.streams_api import StreamsApi

def sysinputs():
	s=SysteminputsApi()
	slist = s.list()
	print(slist)

def apiclnt():
	a=ApiClient()
	print(a)

def search(q, range):
	search = SearchuniversalrelativeApi()
	# q='RemoteMGNT'
	# range=(86400)
	res = search.search_relative(q, range)
	logger.info(f'[s] searchres: {res.total_results} q={q}')
	return res

if __name__ == '__main__':
	streams = StreamsApi()
	sres = search('action:ssl\-login\-fail', 86400)
	print(sres)
