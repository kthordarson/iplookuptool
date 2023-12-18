#!/usr/bin/python
import sys
import os
import argparse
import requests
import socket
import json
from ipaddress import ip_address
from myglapi.rest import ApiException

from modules.virustotal import get_virustotal_info, get_virustotal_comments, get_virustotal_scanurls, get_virustotal_urlinfo, get_vt_ipinfo
from modules.abuseipdb import get_abuseipdb_data
from modules.ipwhois import get_ipwhois
from modules.spamlookup import spam_lookup
from modules.graylog import graylog_search
from modules.defender import get_aad_token, search_remote_ip, search_DeviceNetworkEvents, get_indicators, DefenderException, TokenException
from modules.azurelogs import get_azure_signinlogs
from modules.xforce import get_xforce_ipreport
from modules.urlscanio import search_urlscanio

# todo urlscan.io, fortiguard, abuse.ch
# done add graylog, azure, defender, xforce

try:
	from loguru import logger
except ImportError as e:
	logger.error(f'missing loguru package')
	os._exit(-1)

if __name__ == '__main__':
	parsedargs = argparse.ArgumentParser(description="ip address lookup")
	parsedargs.add_argument('--host', help="ipaddress/host to lookup", type=str, metavar='ipaddr')
	parsedargs.add_argument('--vturl', help="virustotal url lookup", type=str )
	parsedargs.add_argument('--ipwhois', help="ipwhois lookup", action='store_true', default=False)
	parsedargs.add_argument('-vt', '--virustotal', help="virustotal lookup", action='store_true', default=False, dest='virustotal')
	parsedargs.add_argument('--spam', help="spam lookup", action='store_true', default=False)
	parsedargs.add_argument('-abip', '--abuseipdb', help="abuseipdb lookup", action='store_true', default=False, dest='abuseipdb')
	parsedargs.add_argument('-us', '--urlscanio', help="urlscanio lookup", action='store_true', default=False, dest='urlscanio')
	parsedargs.add_argument('--graylog', help="search in graylog", action='store_true', default=False, dest='graylog')
	parsedargs.add_argument('--ftgd_blk', help="get ftgd_blk from graylog", action='store_true', default=False, dest='ftgd_blk')
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
		logger.warning(f'[!] {e} {type(e)} for address {args.host}')
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

	if args.urlscanio:
		urlscandata = search_urlscanio(args.host)

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
		print(f'xforceinfo score {xscore}: spamscore={spamscore} scanscore:{scanscore} anonscore:{anonscore} dynascore:{dynascore} malwscore:{malwscore} botsscore:{botsscore} boccscore:{boccscore} crmiscore:{crmiscore}')

	if args.vturl:
		infourl = get_virustotal_scanurls(args.vturl)
		print(f'getting info from vt url: {infourl}')
		vturlinfo = get_virustotal_urlinfo(infourl)
		resultdata = vturlinfo.get('data').get('attributes').get('results')
		print(f"vt url info {len(resultdata)}: {vturlinfo.get('data').get('attributes').get('stats')}")
		for vendor in resultdata:
			if resultdata.get(vendor).get('category') == 'malicious':
				print(f"\tVendor: {vendor} result: {resultdata.get(vendor).get('result')} method: {resultdata.get(vendor).get('method')} ")

	if args.ipwhois and ipaddress:
		whois_info = get_ipwhois(args.host)
		print(f'whois: {whois_info}')

	if args.virustotal:
		vtinfo = get_vt_ipinfo(args.host)
		if vtinfo:
			vt_las = vtinfo.last_analysis_stats
			vt_res = vtinfo.last_analysis_results
			print(f'vt asowner: {vtinfo.as_owner} vtvotes: {vtinfo.total_votes}')
			print(f'vt last_analysis_stats: {vt_las}')
			for vendor in vt_res:
				if vt_res.get(vendor).get('category') == 'malicious':
					print(f"\tVendor: {vendor} result: {vt_res.get(vendor).get('result')} method: {vt_res.get(vendor).get('method')} ")

	if args.abuseipdb:
		abuseipdbdata = get_abuseipdb_data(args.host)
		if abuseipdbdata:
			print(f'abuseipdb Reports: {abuseipdbdata.get("data").get("totalReports")} abuseConfidenceScore: {abuseipdbdata.get("data").get("abuseConfidenceScore")} isp: {abuseipdbdata.get("data").get("isp")} country: {abuseipdbdata.get("data").get("countryCode")}')
			print(f'\tabuseipdb hostname: {abuseipdbdata.get("data").get("hostnames")} domain: {abuseipdbdata.get("data").get("domain")} tor: {abuseipdbdata.get("data").get("isTor")}')

	if args.graylog:
		searchquery = f'srcip:{args.host} OR dstip:{args.host} OR remip:{args.host}'
		try:
			results = graylog_search(query=searchquery, range=86400)
		except ApiException as e:
			logger.warning(f'graylog search error: {e}')
			raise e
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			results = None
		if results:
			print(f'graylog results: {results.total_results}')
			for res in results.messages[:args.maxoutput]:
				print(f"\t{res.get('message').get('timestamp')} {res.get('message').get('msg')} {res.get('message').get('action')} {res.get('message').get('srcip')} {res.get('message').get('dstip')} {res.get('message').get('url')}")

	if args.ftgd_blk:
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

	if args.azure:
		logdata = get_azure_signinlogs(args.host)
		print(f'azure signinlogs: {len(logdata)}')
		if len(logdata) > 0:
			for logentry in logdata[:args.maxoutput]:
				timest = logentry.get('TimeGenerated')
				status = json.loads(logentry.get('Status'))
				print(f"\t {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")

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
					print(f'indicator found: type: {ind.get("indicatorType")} {ind.get("action")} {ind.get("createdBy")}')
			else:
				print(f'no indicator found: {len(indicators)}')
			try:
				defenderdata = search_DeviceNetworkEvents(token, args.host, limit=100, maxdays=3)
				print(f"defender results: {len(defenderdata.get('Results'))}")
				results = defenderdata.get('Results')
				for res in results[:args.maxoutput]:
					print(f"\t{res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} ")
			except (DefenderException, TokenException) as e:
				logger.error(e)
				os._exit(-1)
			#print(f'results: {results}')
