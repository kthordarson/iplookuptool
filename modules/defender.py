import os
import aiohttp
from loguru import logger

class SchemaException(Exception):
	pass

class TokenException(Exception):
	pass

class WrongReasonException(Exception):
	pass

class DefenderException(Exception):
	pass

async def get_aad_token():
	"""
	returns aadtoken
	Must set enviorment variables with valid credentials for the registered azure enterprise application
	"""
	appid = os.environ.get('AZURE_CLIENT_ID')
	tenantid = os.environ.get('AZURE_TENANT_ID')
	value = os.environ.get('AZURE_CLIENT_SECRET')
	if not appid or not tenantid or not value:
		raise TokenException('Missing authinfo....')
	url = f"https://login.microsoftonline.com/{tenantid}/oauth2/token"
	resourceappiduri = 'https://api-eu.securitycenter.microsoft.com'
	body = {'resource': resourceappiduri, 'client_id': appid,
			'client_secret': value, 'grant_type': 'client_credentials'}
	
	try:
		async with aiohttp.ClientSession() as session:
			async with session.post(url, data=body) as response:
				jsonresponse = await response.json()
				aadtoken = jsonresponse["access_token"]
				return aadtoken
	except aiohttp.ClientError as e:
		logger.error(e)
		raise TokenException(f'{e} {type(e)} Error getting token appid:{appid} tid:{tenantid} v:{value} ')
	except Exception as e:
		logger.error(f'{e} {type(e)} Error getting token appid:{appid} tid:{tenantid} v:{value} ')
		raise TokenException(f'Error getting token {e} appid:{appid} tid:{tenantid} v:{value} ')


async def search_remote_ip(remoteip, aadtoken, limit=100, maxdays=3):
	url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
	# query = f'DeviceNetworkEvents | where RemoteUrl contains "{remoteurl}"'
	query = f"""let ip = "{remoteip}";search in (DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents, EmailEvents, IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents, CloudAppEvents, AADSignInEventsBeta, AADSpnSignInEventsBeta) Timestamp between (ago({maxdays}d) .. now()) and RemoteIP == ip | take {limit} """
	data = {'Query': query}
	# print(f'query = {query}')
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'Authorization': "Bearer " + aadtoken
	}
	async with aiohttp.ClientSession() as session:
		async with session.post(url, json=data, headers=headers) as response:
			jresp = await response.json()
			return jresp

async def search_remote_url(remoteurl, aadtoken, limit=100, maxdays=3):
	url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
	query = f'DeviceNetworkEvents | where RemoteUrl contains "{remoteurl}"'
	data = {'Query': query}
	# print(f'query = {query}')
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'Authorization': "Bearer " + aadtoken
	}
	try:
		async with aiohttp.ClientSession() as session:
			async with session.post(url, json=data, headers=headers) as response:
				jresp = await response.json()
				return jresp
	except (aiohttp.ClientError, ConnectionResetError) as e:
		logger.error(f'[search_remote_url] {type(e)} {e} url = {url}')
		return None

async def search_devicenetworkevents(aadtoken, remoteip, limit=100, maxdays=3):
	url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
	# query = f'DeviceNetworkEvents | where RemoteUrl contains "{remoteurl}"'
	query = f"""let ip = "{remoteip}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """
	data = {'Query': query}
	# print(f'query = {query}')
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'Authorization': "Bearer " + aadtoken
	}
	try:
		async with aiohttp.ClientSession() as session:
			async with session.post(url, json=data, headers=headers) as response:
				jresp = await response.json()
				return jresp
	except aiohttp.ClientError as e:
		logger.error(f'{type(e)} {e} url = {url}')
		raise DefenderException(f'{type(e)} {e} url = {url}')


async def get_indicators(aadtoken, host=None):
	# todo filter by host
	"""
	Get list of indicators from Office365 defender
	Params:
	aadToken: auth token
	Returns: json object of alerts
	"""
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'Authorization': "Bearer " + aadtoken
	}
	# baseurl = "https://api-eu.securitycenter.microsoft.com/api/"
	apiurl = "https://api-eu.securitycenter.microsoft.com/api/Indicators"
	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(apiurl, headers=headers) as response:
				if response.status == 200:
					json_response = await response.json()
					try:
						json_values = json_response['value']
					except KeyError as e:
						logger.warning(f'{type(e)} {e} {apiurl} {json_response}')
						json_values = json_response
					# logger.info(f'{apiurl} json_values = {len(json_values)} {type(json_values)}')
					return json_values
				elif response.status == 403:
					json_err = await response.json()
					logger.warning(f"responsecode={response.status} {json_err.get('error').get('code')} {json_err.get('error').get('message')}  apiurl={apiurl}")
				elif response.status == 404:
					response_content = await response.text()
					logger.error(f'notfound responsecode={response.status} response.content={response_content}  apiurl={apiurl}')
				elif response.status == 400:
					response_content = await response.text()
					logger.error(f'responsecode={response.status} response.content={response_content} apiurl={apiurl}')
				else:
					logger.error(f'unknown status responsecode={response.status}  apiurl={apiurl}')
	except aiohttp.ClientError as e:
		logger.error(f'{type(e)} {e} url = {apiurl}')

