import os
import json
import urllib.request
import urllib.parse
from urllib.error import HTTPError
import requests
from loguru import logger

class SchemaException(Exception):
	pass

class TokenException(Exception):
	pass

class WrongReasonException(Exception):
	pass

class DefenderException(Exception):
	pass

def get_aad_token():
	"""
	returns aadtoken
	Must set enviorment variables with valid credentials for the registered azure enterprise application
	"""
	AppID = os.environ.get('AZURE_CLIENT_ID')
	TenantID = os.environ.get('AZURE_TENANT_ID')
	Value = os.environ.get('AZURE_CLIENT_SECRET')
	if not AppID or not TenantID or not Value:
		raise TokenException('Missing authinfo....')
	url = f"https://login.microsoftonline.com/{TenantID}/oauth2/token"
	resourceAppIdUri = 'https://api-eu.securitycenter.microsoft.com'
	body = {'resource': resourceAppIdUri, 'client_id': AppID,
			'client_secret': Value, 'grant_type': 'client_credentials'}
	data = urllib.parse.urlencode(body).encode("utf-8")
	req = urllib.request.Request(url, data)
	try:
		response = urllib.request.urlopen(req)
	except HTTPError as e:
		logger.error(e)
		raise TokenException(f'{e} {type(e)} Error getting token appid:{AppID} tid:{TenantID} v:{Value} ')
	except Exception as e:
		logger.error(f'{e} {type(e)} Error getting token appid:{AppID} tid:{TenantID} v:{Value} ')
		raise TokenException(f'Error getting token {e} appid:{AppID} tid:{TenantID} v:{Value} ')
	jsonResponse = json.loads(response.read())
	aadToken = jsonResponse["access_token"]
	# logger.debug(f'got aadtoken: {len(aadToken)}')
	return aadToken


def search_remote_ip(remoteip, aadtoken, limit=100, maxdays=3):
	url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
	#query = f'DeviceNetworkEvents | where RemoteUrl contains "{remoteurl}"'
	query = f"""let ip = "{remoteip}";search in (DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents, EmailEvents, IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents, CloudAppEvents, AADSignInEventsBeta, AADSpnSignInEventsBeta) Timestamp between (ago({maxdays}d) .. now()) and RemoteIP == ip | take {limit} """
	data = json.dumps({'Query': query}).encode("utf-8")
	# print(f'query = {query}')
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'Authorization': "Bearer " + aadtoken
	}
	req = urllib.request.Request(url, data, headers)
	resp = urllib.request.urlopen(req)
	jresp = json.loads(resp.read())
	# print(f"results: {len(jresp.get('Results'))}")
	return jresp

def search_remote_url(remoteurl, aadtoken, limit=100, maxdays=3):
	url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
	query = f'DeviceNetworkEvents | where RemoteUrl contains "{remoteurl}"'
	data = json.dumps({'Query': query}).encode("utf-8")
	# print(f'query = {query}')
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'Authorization': "Bearer " + aadtoken
	}
	req = urllib.request.Request(url, data, headers)
	try:
		resp = urllib.request.urlopen(req)
	except (ConnectionResetError, urllib.error.URLError) as e:
		logger.error(f'[search_remote_url] {type(e)} {e} url = {url}')
		return None
	jresp = json.loads(resp.read())
	# print(f"results: {len(jresp.get('Results'))}")
	return jresp

def search_DeviceNetworkEvents(aadtoken, remoteip, limit=100, maxdays=3):
	url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
	#query = f'DeviceNetworkEvents | where RemoteUrl contains "{remoteurl}"'
	query = f"""let ip = "{remoteip}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """
	data = json.dumps({'Query': query}).encode("utf-8")
	# print(f'query = {query}')
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'Authorization': "Bearer " + aadtoken
	}
	req = urllib.request.Request(url, data, headers)
	try:
		resp = urllib.request.urlopen(req)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {url}')
		raise DefenderException(f'{type(e)} {e} url = {url}')
	jresp = json.loads(resp.read())
	# print(f"results: {len(jresp.get('Results'))}")
	return jresp


def get_indicators(aadtoken, host=None):
	# todo filter by host
	"""
	Get list of indicators from Office365 defender
	Params:
	aadToken: auth token
	Returns: json object of alerts
	"""
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + aadtoken
		})
	# baseurl = "https://api-eu.securitycenter.microsoft.com/api/"
	apiurl = "https://api-eu.securitycenter.microsoft.com/api/Indicators"
	try:
		response = session.get(apiurl)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {apiurl}')
	if response.status_code == 200:
		json_response = json.loads(response.content)
		try:
			json_values = json_response['value']
		except KeyError as e:
			logger.warning(f'{type(e)} {e} {apiurl} {json_response}')
			json_values = json_response
		# logger.info(f'{apiurl} json_values = {len(json_values)} {type(json_values)}')
		return json_values
	elif response.status_code == 403:
		json_err = json.loads(response.content)
		logger.warning(f"responsecode={response.status_code} {json_err.get('error').get('code')} {json_err.get('error').get('message')}  apiurl={apiurl}")
	elif response.status_code == 404:
		#json_err = json.loads(response.content)
		logger.error(f'notfound responsecode={response.status_code} response.content={response.content}  apiurl={apiurl}')
	elif response.status_code == 400:
		#json_err = json.loads(response.content)
		logger.error(f'responsecode={response.status_code} response.content={response.content} apiurl={apiurl}')
	else:
		logger.error(f'unknown status responsecode={response.status_code}  apiurl={apiurl}')

