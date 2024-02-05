#!/usr/bin/python
import sys
import os
import argparse
import json

try:
	from loguru import logger
except ImportError as e:
	logger.error(f'missing loguru package')
	os._exit(-1)

try:
	from colorama import Fore, Back, Style
except ImportError as e:
	logger.error(f'missing colorama package')
	os._exit(-1)

try:
	from ipaddress import ip_address
except ImportError as e:
	logger.error(f'missing ipaddress package')
	os._exit(-1)

try:
	from ipwhois.exceptions import HostLookupError, HTTPLookupError
except ImportError as e:
	logger.error(f'missing ipwhois package')
	os._exit(-1)

try:
	from myglapi.rest import ApiException
except ImportError as e:
	logger.error(f'missing myglapi package')
	os._exit(-1)

from modules.virustotal import get_virustotal_info, get_virustotal_comments, get_virustotal_scanurls, get_virustotal_urlinfo, get_vt_ipinfo
from modules.abuseipdb import get_abuseipdb_data
from modules.ipwhois import get_ipwhois
from modules.spamlookup import spam_lookup
from modules.graylog import graylog_search
from modules.defender import get_aad_token, search_remote_ip, search_DeviceNetworkEvents, get_indicators, DefenderException, TokenException, search_remote_url
from modules.azurelogs import get_azure_signinlogs, get_azure_signinlogs_failed
from modules.xforce import get_xforce_ipreport
from modules.urlscanio import search_urlscanio

# todo urlscan.io, fortiguard, abuse.ch
# done add graylog, azure, defender, xforce


if __name__ == '__main__':
	parsedargs = argparse.ArgumentParser(description="ip address lookup")
	parsedargs.add_argument('--host', help="ipaddress/host to lookup", type=str, metavar='ipaddr')
	parsedargs.add_argument('--url', help="url to lookup", type=str, metavar='url')
	parsedargs.add_argument('--vturl', help="virustotal url lookup", type=str )
	parsedargs.add_argument('--ipwhois', help="ipwhois lookup", action='store_true', default=False)
	parsedargs.add_argument('-vt', '--virustotal', help="virustotal lookup", action='store_true', default=False, dest='virustotal')
	parsedargs.add_argument('--spam', help="spam lookup", action='store_true', default=False)
	parsedargs.add_argument('-abip', '--abuseipdb', help="abuseipdb lookup", action='store_true', default=False, dest='abuseipdb')
	parsedargs.add_argument('-us', '--urlscanio', help="urlscanio lookup", action='store_true', default=False, dest='urlscanio')
	parsedargs.add_argument('--graylog', help="search in graylog", action='store_true', default=False, dest='graylog')
	parsedargs.add_argument('--ftgd_blk', help="get ftgd_blk from graylog", action='store_true', default=False, dest='ftgd_blk')
	parsedargs.add_argument('--sslvpnloginfail', help="get sslvpnloginfail from graylog", action='store_true', default=False, dest='sslvpnloginfail')
	parsedargs.add_argument('-def', '--defender', help="search in defender", action='store_true', default=False, dest='defender')
	parsedargs.add_argument('-az', '--azure', help="search azurelogs", action='store_true', default=False, dest='azure')
	parsedargs.add_argument('-xf', '--xforce', help="search xforce", action='store_true', default=False, dest='xforce')

	parsedargs.add_argument('--maxoutput', help="limit output", default=10)
	parsedargs.add_argument('--all', help="use all lookups", action='store_true', default=False)
	args = parsedargs.parse_args()
	vtinfo = None
	abuseipdbdata = None
	try:
		ipaddress = ip_address(args.host).exploded
	except ValueError as e:
		# logger.warning(f'[!] {e} {type(e)} for address {args.host}')
		ipaddress = None

	if args.all:
		args.ipwhois = True
		args.virustotal = True
		args.abuseipdb = True
		args.spam = True
		args.defender = True
		args.graylog = True
		args.azure = True
		args.urlscanio = True
		args.xforce = True
	if ip_address(args.host).is_private:
		# if ipaddreses is private, skip public lookups
		args.ipwhois = False
		args.virustotal = False
		args.abuseipdb = False
		args.spam = False
		args.urlscanio = False
		args.xforce = False
	if args.url:
		# search logs for remoteurl
		infourl = get_virustotal_scanurls(args.url)
		print(f'{Fore.BLUE}getting info from vt url: {infourl}')
		vturlinfo = get_virustotal_urlinfo(infourl)
		resultdata = vturlinfo.get('data').get('attributes').get('results')
		print(f"vt url info {len(resultdata)}: {vturlinfo.get('data').get('attributes').get('stats')}")
		for vendor in resultdata:
			if resultdata.get(vendor).get('category') == 'malicious':
				print(f"\tVendor: {vendor} result: {resultdata.get(vendor).get('result')} method: {resultdata.get(vendor).get('method')} ")
		try:
			token = get_aad_token()
			defenderdata = search_remote_url(args.url, token, limit=100, maxdays=3)
			print(f"defender data: {len(defenderdata.get("Results"))} ")
			if len(defenderdata.get('Results')) >= 1:
				results = defenderdata.get('Results')
				for res in results[:args.maxoutput]:
					print(f"\t{res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} ")
		except (DefenderException, TokenException) as e:
			logger.error(e)
			os._exit(-1)


	if args.urlscanio:
		urlscandata = search_urlscanio(args.host)
		print(f'{Fore.BLUE}urlscanio data: {Fore.GREEN}{len(urlscandata)} results: {urlscandata.get("total")} ')

	if args.xforce:
		xfi = get_xforce_ipreport(args.host)
		spamscore = sum([k.get('cats').get('Spam',0) for k in xfi.get('history') ])
		scanscore = sum([k.get('cats').get('Scanning IPs',0) for k in xfi.get('history') ])
		anonscore = sum([k.get('cats').get('Anonymisation Services',0) for k in xfi.get('history') ])
		dynascore = sum([k.get('cats').get('Dynamic IPs',0) for k in xfi.get('history') ])
		malwscore = sum([k.get('cats').get('Malware',0) for k in xfi.get('history') ])
		botsscore = sum([k.get('cats').get('Bots',0) for k in xfi.get('history') ])
		boccscore = sum([k.get('cats').get('Botnet Command and Control Server',0) for k in xfi.get('history') ])
		crmiscore = sum([k.get('cats').get('Cryptocurrency Mining',0) for k in xfi.get('history') ])
		xscore = xfi.get('score')
		print(f'{Fore.BLUE}xforceinfo {Fore.GREEN}score {xscore}: spamscore={spamscore} scanscore:{scanscore} anonscore:{anonscore} dynascore:{dynascore} malwscore:{malwscore} botsscore:{botsscore} boccscore:{boccscore} crmiscore:{crmiscore}')

	if args.vturl:
		infourl = get_virustotal_scanurls(args.vturl)
		print(f'{Fore.BLUE}getting info from vt url:{Fore.CYAN} {infourl}')
		vturlinfo = get_virustotal_urlinfo(infourl)
		resultdata = vturlinfo.get('data').get('attributes').get('results')
		print(f"{Fore.BLUE}vt url info {Fore.GREEN}{len(resultdata)}: {vturlinfo.get('data').get('attributes').get('stats')}")
		for vendor in resultdata:
			if resultdata.get(vendor).get('category') == 'malicious':
				print(f"{Fore.BLUE}\tVendor: {vendor} {Fore.CYAN}result: {resultdata.get(vendor).get('result')} method: {resultdata.get(vendor).get('method')} ")

	if args.ipwhois and ipaddress:
		print(f'{Fore.BLUE}ipwhois lookup for {Fore.GREEN}{args.host} ipaddress: {ipaddress}')
		ipaddress = ip_address(args.host)
		if ipaddress.is_global:
			whois_info = get_ipwhois(args.host)
			print(f'{Fore.BLUE}whois:{Fore.GREEN} {whois_info}')
		elif ipaddress.is_private:
			print(f'{Fore.YELLOW}private address: {ipaddress}')

	if args.virustotal:
		vtinfo = get_vt_ipinfo(args.host)
		if vtinfo:
			vt_las = vtinfo.last_analysis_stats
			vt_res = vtinfo.last_analysis_results
			try:
				vt_aso = vtinfo.as_owner
				vt_tv = vtinfo.total_votes
			except AttributeError as e:
				logger.error(f'virustotal error: {e} {vt_las} {vt_res} vtinfo: {vtinfo}' )
				vt_aso = None
				vt_tv = None
			print(f'{Fore.BLUE}vt asowner:{Fore.GREEN} {vt_aso} vtvotes: {vt_tv} vt last_analysis_stats: {vt_las}')
			for vendor in vt_res:
				if vt_res.get(vendor).get('category') == 'malicious':
					print(f"{Fore.BLUE}\tVendor: {vendor} {Fore.CYAN} result: {vt_res.get(vendor).get('result')} method: {vt_res.get(vendor).get('method')} ")

	if args.abuseipdb:
		abuseipdbdata = get_abuseipdb_data(args.host)
		if abuseipdbdata:
			print(f'{Fore.BLUE}abuseipdb Reports:{Fore.CYAN} {abuseipdbdata.get("data").get("totalReports")} abuseConfidenceScore: {abuseipdbdata.get("data").get("abuseConfidenceScore")} isp: {abuseipdbdata.get("data").get("isp")} country: {abuseipdbdata.get("data").get("countryCode")}')
			print(f'{Fore.BLUE}\tabuseipdb hostname:{Fore.CYAN} {abuseipdbdata.get("data").get("hostnames")} domain: {abuseipdbdata.get("data").get("domain")} tor: {abuseipdbdata.get("data").get("isTor")}')

	if args.graylog:
		searchquery = f'srcip:{args.host} OR dstip:{args.host} OR remip:{args.host}'
		try:
			results = graylog_search(query=searchquery, range=86400)
		except ApiException as e:
			logger.warning(f'graylog search error: {e}')
			results = None
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			results = None
		if results:
			print(f'{Fore.GREEN}graylog results:{Fore.LIGHTGREEN_EX} {results.total_results}')
			for res in results.messages[:args.maxoutput]:
				print(f"{Fore.BLUE}\tts:{res.get('message').get('timestamp')} {Fore.GREEN} msg:{res.get('message').get('msg')} {Fore.CYAN} action:{res.get('message').get('action')} srcip:{res.get('message').get('srcip')} dstip:{res.get('message').get('dstip')} url:{res.get('message').get('url')}")
			print(Style.RESET_ALL)

	if args.sslvpnloginfail and args.graylog:
		searchquery = 'action:ssl-login-fail'
		try:
			results = graylog_search(query=searchquery, range=86400)
		except ApiException as e:
			logger.warning(f'graylog search error: {e}')
			results = None
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			results = None
		if results:
			ipaddres_set = set([k.get('message').get('remip') for k in results.messages])
			print(f'graylog sslvpnloginfail results: {results.total_results} ipaddres_set: {len(ipaddres_set)}')
			for res in results.messages[:args.maxoutput]:
				print(f"\t{res.get('message').get('timestamp')} {res.get('message').get('msg')} {res.get('message').get('action')} {res.get('message').get('user')} {res.get('message').get('remip')} {res.get('message').get('source')}")
			token = get_aad_token()
			for addr in ipaddres_set:
				print(f'serching logs for {addr}')
				defenderdata = search_DeviceNetworkEvents(token, addr, limit=100, maxdays=1)
				azuredata = get_azure_signinlogs(addr)
				azuredata_f = get_azure_signinlogs_failed(addr)
				glq = f'srcip:{addr} OR dstip:{addr} OR remip:{addr}'
				glres = graylog_search(query=glq, range=86400)
				print(f'\tresults for {addr} defender: {len(defenderdata.get("Results"))} azure: {len(azuredata)} azure failed: {len(azuredata_f)} graylog: {glres.total_results}')
				if len(defenderdata.get("Results")) > 0:
					print(f'defender found {len(defenderdata.get("Results"))} for {addr}')
					results = defenderdata.get('Results')
					for res in results[:args.maxoutput]:
						print(f"\t{res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} ")
				if len(azuredata) > 0:
					print(f'azure found {len(azuredata)}')
					for logentry in azuredata[:args.maxoutput]:
						timest = logentry.get('TimeGenerated')
						status = json.loads(logentry.get('Status'))
						print(f"\t {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")
				if len(azuredata_f) > 0:
					print(f'azure failed signins found {len(azuredata_f)}')
					for logentry in azuredata_f[:args.maxoutput]:
						timest = logentry.get('TimeGenerated')
						status = json.loads(logentry.get('Status'))
						print(f"\t {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")

	if args.ftgd_blk and args.graylog:
		searchquery = f'eventtype:ftgd_blk'
		try:
			results = graylog_search(query=searchquery, range=86400)
		except ApiException as e:
			logger.warning(f'graylog search error: {e}')
			raise e
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			results = None
		if results:
			ipaddres_set = set([k.get('message').get('dstip') for k in results.messages])
			print(f'graylog results: {results.total_results} ipaddres_set: {len(ipaddres_set)}')
			token = get_aad_token()
			indicators = get_indicators(token, args.host)
			for addr in ipaddres_set:
				print(f'serching logs for {addr}')
				[print(f'\tindicator for {addr} found: {k}') for k in indicators if addr in str(k.values())]
				defenderdata = search_DeviceNetworkEvents(token, addr, limit=100, maxdays=1)
				azuredata = get_azure_signinlogs(addr)
				azuredata_f = get_azure_signinlogs_failed(addr)
				glq = f'srcip:{addr} OR dstip:{addr} OR remip:{addr}'
				glres = graylog_search(query=glq, range=86400)
				# print(f'defender found {len(defenderdata.get("Results"))} azure found {len(azuredata)} graylog found {glres.total_results}')
				if glres.total_results > 0:
					print(f'graylog results: {glres.total_results}')
					for res in glres.messages[:args.maxoutput]:
						print(f"\t{res.get('message').get('timestamp')} {res.get('message').get('msg')} {res.get('message').get('action')} {res.get('message').get('srcip')} {res.get('message').get('dstip')} {res.get('message').get('url')}")
				if len(defenderdata.get("Results")) > 0:
					print(f'defender found {len(defenderdata.get("Results"))} for {addr}')
					results = defenderdata.get('Results')
					for res in results[:args.maxoutput]:
						print(f"\t{res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} ")
				if len(azuredata) > 0:
					print(f'azure found {len(azuredata)}')
					for logentry in azuredata[:args.maxoutput]:
						timest = logentry.get('TimeGenerated')
						status = json.loads(logentry.get('Status'))
						print(f"\t {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")
				if len(azuredata_f) > 0:
					print(f'azure failed signins found {len(azuredata_f)}')
					for logentry in azuredata_f[:args.maxoutput]:
						timest = logentry.get('TimeGenerated')
						status = json.loads(logentry.get('Status'))
						print(f"\t {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")

	if args.azure:
		logdata = get_azure_signinlogs(args.host)
		if len(logdata) >= 1:
			print(f'{Fore.BLUE}azure signinlogs:{Fore.GREEN}{len(logdata)}')
			if len(logdata) > 0:
				for logentry in logdata[:args.maxoutput]:
					timest = logentry.get('TimeGenerated')
					status = json.loads(logentry.get('Status'))
					print(f"{Fore.CYAN}\t {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")

	if args.defender:
		try:
			token = get_aad_token()
		except Exception as e:
			logger.error(e)
			os._exit(-1)
		if token:
			try:
				indicators = get_indicators(token, args.host)
			except (DefenderException, TokenException) as e:
				logger.error(e)
				os._exit(-1)
			# if len([k for k in indicators if k.get('indicatorValue') == args.host]) <= 1:
			if len([k for k in indicators if args.host in  str(k.values())]) >= 1:
				indx = [k for k in indicators if k.get('indicatorValue') == args.host]
				for ind in indx:
					print(f'{Fore.RED}indicator found: type: {ind.get("indicatorType")} {ind.get("action")} {ind.get("createdBy")}')
			else:
				print(f'{Fore.YELLOW}no indicator found for {Fore.GREEN}{args.host}{Style.RESET_ALL}')
			try:
				defenderdata = search_DeviceNetworkEvents(token, args.host, limit=100, maxdays=3)
				if len(defenderdata.get('Results')) >= 1:
					print(f"{Fore.BLUE}defender results:{Fore.GREEN} {len(defenderdata.get('Results'))}")
					results = defenderdata.get('Results')
					for res in results[:args.maxoutput]:
						print(f"{Fore.CYAN}{'':2} {res.get('Timestamp')}\n\tdevice: {res.get('DeviceName')} user: {res.get('InitiatingProcessAccountName')} remip: {res.get('RemoteIP')}:{res.get('RemotePort')} localip: {res.get('LocalIP')} action: {res.get('ActionType')} \n\tremoteurl: {res.get('RemoteUrl')} upn:{res.get('InitiatingProcessAccountUpn')} {Style.RESET_ALL}")
			except (DefenderException, TokenException) as e:
				logger.error(e)
				os._exit(-1)
			#print(f'results: {results}')
