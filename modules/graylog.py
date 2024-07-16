import os
from urllib3.exceptions import MaxRetryError
from myglapi.apis.searchuniversalrelative_api import SearchuniversalrelativeApi
from myglapi.rest import ApiException
from myglapi import rest
GRAYLOGAPIKEY = os.environ.get('GRAYLOGAPIKEY')
def graylog_search(query, range=86400):
	search = SearchuniversalrelativeApi()
	# q='RemoteMGNT'
	# range=(86400)
	res = None
	try:
		res = search.search_relative(query, range)
	except (ApiException, rest.ApiException) as e:
		# logger.warning(f'graylog search error: {e} {type(e)}')
		raise ApiException(e)
	except MaxRetryError as e:
		# warning.error(f'graylog search error: {e} {type(e)}')
		raise ApiException(e)
	except Exception as e:
		# logger.error(f'graylog search error: {e} {type(e)}')
		raise e
	# logger.info(f'[s] searchres: {res.total_results} q={query} range={range}')
	return res

if __name__ == '__main__':
	pass
