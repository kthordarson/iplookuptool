#!/usr/bin/env python3
import asyncio
import pandas as pd
import os
import argparse
import json
from loguru import logger
from colorama import Fore, Style
from ipaddress import ip_address
from myglapi.rest import ApiException
from modules.virustotal import get_virustotal_scanurls, get_virustotal_urlinfo, get_vt_ipinfo
from modules.abuseipdb import get_abuseipdb_data
from modules.ipwhois import get_ipwhois
from modules.graylog import graylog_search, graylog_search_ip, summarize_graylog_results, print_graylog_summary
from modules.defender import get_aad_token, search_devicenetworkevents, get_indicators, DefenderException, TokenException, search_remote_url
from modules.azurelogs import get_azure_signinlogs, get_azure_signinlogs_failed
# from modules.xforce import get_xforce_ipreport
from modules.urlscanio import search_urlscanio
import urllib3
urllib3.disable_warnings()

def get_args():
	parser = argparse.ArgumentParser(description="ip address lookup")
	parser.add_argument('--host', help="ipaddress/host to lookup", type=str, metavar='ipaddr')
	parser.add_argument('--url', help="url to lookup", type=str, metavar='url')
	parser.add_argument('--vturl', help="virustotal url lookup", type=str)
	parser.add_argument('--ipwhois', help="ipwhois lookup", action='store_true', default=False)
	parser.add_argument('-vt', '--virustotal', help="virustotal lookup", action='store_true', default=False, dest='virustotal')
	parser.add_argument('--spam', help="spam lookup", action='store_true', default=False)
	parser.add_argument('-abip', '--abuseipdb', help="abuseipdb lookup", action='store_true', default=False, dest='abuseipdb')
	parser.add_argument('-us', '--urlscanio', help="urlscanio lookup", action='store_true', default=False, dest='urlscanio')
	parser.add_argument('--graylog', help="search in graylog", action='store_true', default=False, dest='graylog')
	parser.add_argument('--ftgd_blk', help="get ftgd_blk from graylog", action='store_true', default=False, dest='ftgd_blk')
	parser.add_argument('--sslvpnloginfail', help="get sslvpnloginfail from graylog", action='store_true', default=False, dest='sslvpnloginfail')
	parser.add_argument('-def', '--defender', help="search in defender", action='store_true', default=False, dest='defender')
	parser.add_argument('-az', '--azure', help="search azurelogs", action='store_true', default=False, dest='azure')
	parser.add_argument('-xf', '--xforce', help="search xforce", action='store_true', default=False, dest='xforce')

	parser.add_argument('--maxoutput', help="limit output", default=10, type=int)
	parser.add_argument('--all', help="use all lookups", action='store_true', default=False)
	parser.add_argument('--debug', help="debug", action='store_true', default=False)
	args = parser.parse_args()
	return parser, args

async def main(args):
	if args.all:
		args.ipwhois = True
		args.virustotal = True
		args.abuseipdb = True
		args.spam = True
		args.defender = True
		args.graylog = True
		args.azure = True
		args.urlscanio = True
		# args.xforce = True

	try:
		ipaddress = ip_address(args.host).exploded
	except ValueError as e:
		logger.warning(f'[!] {e} {type(e)} for address {args.host}')
		return

	if args.url:
		# search logs for remoteurl
		infourl = await get_virustotal_scanurls(args.url)
		vturlinfo = await get_virustotal_urlinfo(infourl)
		vt_url_resultdata = vturlinfo.get('data').get('attributes').get('results')
		try:
			token = await get_aad_token()
			defenderdata = await search_remote_url(args.url, token, limit=100, maxdays=3)
		except (DefenderException, TokenException) as e:
			logger.error(e)
			os._exit(-1)
		finally:
			print(f"{Fore.LIGHTBLUE_EX}vt url info  {Fore.CYAN} {len(vt_url_resultdata)}:{Fore.YELLOW} {vturlinfo.get('data').get('attributes').get('stats')}{Style.RESET_ALL}")
			for vendor in vt_url_resultdata:
				if vt_url_resultdata.get(vendor).get('category') == 'malicious':
					print(f"{Fore.CYAN}   Vendor: {vendor} result: {vt_url_resultdata.get(vendor).get('result')} method: {vt_url_resultdata.get(vendor).get('method')} {Style.RESET_ALL}")
			print(f"{Fore.LIGHTBLUE_EX}defender data:{Fore.YELLOW} {len(defenderdata.get("Results"))} {Style.RESET_ALL}")
			if len(defenderdata.get('Results')) >= 1:
				results = defenderdata.get('Results')
				for res in results[:args.maxoutput]:
					print(f"{Fore.CYAN}   {res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} {Style.RESET_ALL}")

	if args.urlscanio:
		try:
			urlscandata = await search_urlscanio(args.host)
			if urlscandata:
				print(f'{Fore.LIGHTBLUE_EX}urlscanio {Fore.LIGHTBLACK_EX}results:{Fore.YELLOW} {urlscandata.get("total")} ')
				for res in urlscandata.get('results'):
					print(f"{Fore.CYAN} time: {res.get('task').get('time')} vis: {res.get('task').get('visibility')} url: {res.get('task').get('url')} ")
			else:
				logger.warning(f'no urlscanio data for {args.host} urlscandata: {urlscandata}')
		except Exception as e:
			logger.error(f'unhandled {type(e)} {e}')

	if args.xforce:
		try:
			xfi = {}  # get_xforce_ipreport(args.host)
		except Exception as e:
			logger.error(f'xforce error: {e} {type(e)}')
			return None
		if xfi.get('error') == 'Not authorized.':
			logger.error(f'xforce error: {xfi.get("error")} xfi: {xfi}')
		else:
			try:
				spamscore = sum([k.get('cats').get('Spam',0) for k in xfi.get('history')])
				scanscore = sum([k.get('cats').get('Scanning IPs',0) for k in xfi.get('history')])
				anonscore = sum([k.get('cats').get('Anonymisation Services',0) for k in xfi.get('history')])
				dynascore = sum([k.get('cats').get('Dynamic IPs',0) for k in xfi.get('history')])
				malwscore = sum([k.get('cats').get('Malware',0) for k in xfi.get('history')])
				botsscore = sum([k.get('cats').get('Bots',0) for k in xfi.get('history')])
				boccscore = sum([k.get('cats').get('Botnet Command and Control Server',0) for k in xfi.get('history')])
				crmiscore = sum([k.get('cats').get('Cryptocurrency Mining',0) for k in xfi.get('history')])
				xscore = xfi.get('score')
				print(f'{Fore.LIGHTBLUE_EX}xforceinfo:  {Fore.YELLOW}score {xscore}: spamscore={spamscore} scanscore:{scanscore} anonscore:{anonscore} dynascore:{dynascore} malwscore:{malwscore} botsscore:{botsscore} boccscore:{boccscore} crmiscore:{crmiscore}')
			except Exception as e:
				logger.error(f'{e} {type(e)} in xforce xfi: {xfi}')
	if args.vturl:
		infourl = await get_virustotal_scanurls(args.vturl)
		print(f'{Fore.LIGHTBLUE_EX}getting info from vt url:{Fore.CYAN} {infourl}')
		vturlinfo = await get_virustotal_urlinfo(infourl)
		vt_url_resultdata = vturlinfo.get('data').get('attributes').get('results')
		print(f"{Fore.BLUE}vt url info:  {Fore.GREEN}{len(vt_url_resultdata)}: {vturlinfo.get('data').get('attributes').get('stats')}")
		for vendor in vt_url_resultdata:
			if vt_url_resultdata.get(vendor).get('category') == 'malicious':
				print(f"{Fore.BLUE}   Vendor: {vendor} {Fore.CYAN}result: {vt_url_resultdata.get(vendor).get('result')} method: {vt_url_resultdata.get(vendor).get('method')} ")

	if args.ipwhois and ipaddress:
		# print(f'{Fore.LIGHTBLUE_EX}ipwhois lookup for {Fore.CYAN}{args.host} ipaddress: {ipaddress}')
		ipaddress = ip_address(args.host)
		if ipaddress.is_global:
			whois_info = await get_ipwhois(args.host)
			print(f'{Fore.LIGHTBLUE_EX}whois\n\t{Fore.CYAN} {whois_info}')
		elif ipaddress.is_private:
			print(f'{Fore.YELLOW}private address: {ipaddress}')

	if args.virustotal:
		vtinfo = await get_vt_ipinfo(args)
		if vtinfo:
			vt_las = vtinfo.last_analysis_stats
			vt_res = vtinfo.last_analysis_results
			try:
				vt_aso = vtinfo.as_owner if hasattr(vtinfo, 'as_owner') else None
				# vt_aso = vtinfo.as_owner
				vt_tv = vtinfo.total_votes if hasattr(vtinfo, 'total_votes') else None
			except AttributeError as e:
				logger.error(f'virustotal error: {e} {vt_las} {vt_res} vtinfo: {vtinfo}')
				vt_aso = None
				vt_tv = None
			if vt_tv:
				malicious = 0
				try:
					malicious += int(vt_tv.get('malicious',0))
				except Exception as e:
					logger.error(f'{e} {type(e)}')
				try:
					malicious += int(vt_las.get('malicious',0))
				except Exception as e:
					logger.error(f'{e} {type(e)}')
				if malicious > 0:
					vtforecolor = Fore.RED
				else:
					vtforecolor = Fore.GREEN
				# print(f'{Fore.LIGHTBLUE_EX}vt {args.host} asowner:{Fore.CYAN} {vt_aso} vtvotes: {vtforecolor} {vt_tv}  {Fore.CYAN} vt last_analysis_stats: {vt_las}')
				print(f'{Fore.LIGHTBLUE_EX}vt\t{args.host} asowner:{Fore.CYAN} {vt_aso} vtvotes: {vtforecolor} malicious: {malicious}  {Fore.CYAN} vt last_analysis_stats: {vt_las}')
			for vendor in vt_res:
				if vt_res.get(vendor).get('category') == 'malicious':
					print(f"{Fore.BLUE}   Vendor: {vendor} {Fore.CYAN} result: {vt_res.get(vendor).get('result')} method: {vt_res.get(vendor).get('method')} ")

	if args.abuseipdb:
		abuseipdbdata = await get_abuseipdb_data(args.host)
		if abuseipdbdata:
			print(f'{Fore.LIGHTBLUE_EX}abuseipdb Reports:{Fore.CYAN} {abuseipdbdata.get("data").get("totalReports")} abuseConfidenceScore: {abuseipdbdata.get("data").get("abuseConfidenceScore")} isp: {abuseipdbdata.get("data").get("isp")} country: {abuseipdbdata.get("data").get("countryCode")} hostname:{Fore.CYAN} {abuseipdbdata.get("data").get("hostnames")} domain: {abuseipdbdata.get("data").get("domain")} tor: {abuseipdbdata.get("data").get("isTor")}')
			# print(f'{Fore.LIGHTBLUE_EX}   abuseipdb hostname:{Fore.CYAN} {abuseipdbdata.get("data").get("hostnames")} domain: {abuseipdbdata.get("data").get("domain")} tor: {abuseipdbdata.get("data").get("isTor")}')

	if args.graylog:
		try:
			if args.debug:
				logger.debug(f'searching graylog for {args.host}')
			results = await graylog_search_ip(args.host, range=86400)
		except ApiException as e:
			logger.warning(f'graylog search error: {e}')
			results = None
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			results = None
		if results:
			# summary = summarize_graylog_results(results)
			# print(f'summary: {summary.keys()}')
			print_graylog_summary(results)
			df = pd.DataFrame([k['_source'] for k in results.get('hits').get('hits')])		
			# Additional detailed analysis
			if results.get('hits').get('total').get('value') > 0:
				print(f'\n{Fore.LIGHTBLUE_EX}=== Detailed Analysis ==={Style.RESET_ALL}')
				
				# Citrix specific analysis
				if 'citrixtype' in df.columns or 'type' in df.columns:
					if 'citrixtype' in df.columns or (df['type'] == 'citrixtype').any():
						print(f'{Fore.LIGHTBLUE_EX}Citrix NetScaler Data Analysis:')
						
						# Analyze traffic patterns
						if 'Total_bytes_recv' in df.columns and 'Total_bytes_send' in df.columns:
							total_recv = df['Total_bytes_recv'].sum()
							total_sent = df['Total_bytes_send'].sum()
							print(f"  {Fore.CYAN}Total Traffic - Received: {Fore.YELLOW}{total_recv:,} bytes {Fore.CYAN}Sent: {Fore.YELLOW}{total_sent:,} bytes")
						
						# Top destinations
						if 'Destination' in df.columns:
							top_destinations = df['Destination'].value_counts().head(10)
							print(f"  {Fore.CYAN}Top Destinations:")
							for dest, count in top_destinations.items():
								print(f"    {Fore.YELLOW}{dest}: {count}")
						
						# Virtual server analysis
						if 'Vserver' in df.columns:
							vservers = df['Vserver'].value_counts().head(5)
							print(f"  {Fore.CYAN}Virtual Servers:")
							for vserver, count in vservers.items():
								print(f"    {Fore.YELLOW}{vserver}: {count}")
						
						# Source and destination address patterns
						if 'SourceAddress' in df.columns and 'DestinationAddress' in df.columns:
							unique_sources = df['SourceAddress'].nunique()
							unique_dests = df['DestinationAddress'].nunique()
							print(f"  {Fore.CYAN}Connection Diversity - Unique Sources: {Fore.YELLOW}{unique_sources} {Fore.CYAN}Unique Destinations: {Fore.YELLOW}{unique_dests}")
				
				# Time-based analysis
				if 'timestamp' in df.columns:
					df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
					hourly_activity = df['hour'].value_counts().sort_index()
					print(f"  {Fore.CYAN}Hourly Activity Distribution:")
					for hour, count in hourly_activity.head(10).items():
						print(f"    {Fore.YELLOW}Hour {hour:02d}: {count} events")
				
				print(f'{Fore.GREEN}[1] graylog results:{Fore.LIGHTGREEN_EX} {results.get('hits').get('total').get('value')}')
				for res in results.get('hits').get('hits')[:args.maxoutput]:
					res_idx = res.get('_index')
					res_msg = res.get('_source')
					if 'msgraph' in res_idx:
						print(f"{Fore.YELLOW} {res_idx} {res_msg.get('gl2_receive_timestamp')} {res_msg.get('RequestMethod')} {res_msg.get('displayName')} {res_msg.get('IpAddress')} {res_msg.get('dstip')} {res_msg.get('RequestUri')}")
					else:
						print(f"{Fore.YELLOW}{res_idx} {Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} country:{res_msg.get('srccountry')} - {res_msg.get('dstcountry')} {Fore.CYAN} action:{res_msg.get('action')} srcip:{res_msg.get('srcip')} dstip:{res_msg.get('dstip')} transip:{res_msg.get('transip')} service: {res_msg.get('service')} url:{res_msg.get('url')} srcname:{res_msg.get('srcname')}")
					# print(f"   {Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} srccountry:{res_msg.get('srccountry')} {Fore.CYAN} action:{res_msg.get('action')} srcip:{res_msg.get('srcip')} dstip:{res_msg.get('dstip')} service: {res_msg.get('service')} url:{res_msg.get('url')}")
				if 'msg' in df.columns:
					print(f'{Fore.LIGHTBLUE_EX}top 15 actions by srcip:')
					try:
						print(df.groupby(['action', 'msg', 'srcip'])['msg'].agg(['count']).sort_values(by='count', ascending=False).head(15))
					except KeyError as e:
						logger.error(f'KeyError: {e} - check graylog data structure. {df.columns}')

					print(f'{Fore.LIGHTBLUE_EX}top 15 actions by dstip:')
					try:
						print(df.groupby(['action', 'msg', 'dstip'])['msg'].agg(['count']).sort_values(by='count', ascending=False).head(15))
					except KeyError as e:
						logger.error(f'KeyError: {e} - check graylog data structure. {df.columns}')

					print(f'{Fore.LIGHTBLUE_EX}top 15 actions by type and ip:')
					print(df.groupby(['action','type', 'subtype', 'srcip', 'dstip'])['timestamp'].agg(['count']).sort_values(by='count', ascending=False).head(15))
					print(df.groupby(['action', 'srcip'])['srcip'].agg(['count']).sort_values(by='count', ascending=False).head(15))
				if 'citrixtype' in df.columns or 'request' in df.columns:
					print(f'{Fore.LIGHTBLUE_EX}Citrix data found - processing citrixtype column')
					# print(df.groupby(['action', 'srcip'])['srcip'].agg(['count']).sort_values(by='count', ascending=False).head(15))
			else:
				print(f'{Fore.YELLOW}no graylog data ({results.get('hits').get('total').get('value')}) for {Fore.GREEN}{args.host}{Style.RESET_ALL}')
		else:
			print(f'{Fore.YELLOW}no graylog results for {Fore.GREEN}{args.host}{Style.RESET_ALL}')

	if args.sslvpnloginfail and args.graylog:
		searchquery = 'action:ssl-login-fail'
		try:
			results = await graylog_search(query=searchquery, range=86400)
		except ApiException as e:
			logger.warning(f'graylog search error: {e}')
			results = None
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			results = None
		if results:
			ipaddres_set = set([k.get('message').get('remip') for k in results.get('hits').get('hits')])
			print(f'{Fore.LIGHTBLUE_EX}graylog sslvpnloginfail {Fore.CYAN}results: {results.get('hits').get('total').get('value')} ipaddres_set: {len(ipaddres_set)}')
			for res in results.get('hits').get('hits')[:args.maxoutput]:
				print(f"{Fore.YELLOW}   {res_msg.get('timestamp')} {res_msg.get('msg')} {res_msg.get('action')} {res_msg.get('user')} {res_msg.get('remip')} {res_msg.get('source')}")
			token = await get_aad_token()
			for addr in ipaddres_set:
				print(f'{Fore.LIGHTBLUE_EX}serching logs for {Fore.YELLOW}{addr}')
				if args.debug:
					logger.debug(f'searching defender for {addr}')
					maxdays=1
					limit=100
					query = f"""let ip = "{addr}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """
				defenderdata = await search_devicenetworkevents(token, query)
				if args.debug:
					logger.debug(f'defender returned {len(defenderdata.get("Results"))} ... searching azure logs for {addr}')
				azuredata = await get_azure_signinlogs(addr)
				if args.debug:
					logger.debug(f'azure logs returned {len(azuredata)} ... searching azure failed signin logs for {addr}')
				azuredata_f = await get_azure_signinlogs_failed(addr)
				if args.debug:
					logger.debug(f'azure failed signin logs returned {len(azuredata_f)} ... searching graylog for {addr}')
				glres = await graylog_search_ip(addr, range=86400)
				if args.debug:
					logger.debug(f'graylog search returned {glres.get("hits").get("total").get("value")} results for {addr}')
				print(f'{Fore.CYAN}   results for {addr} defender: {len(defenderdata.get("Results"))} azure: {len(azuredata)} azure failed: {len(azuredata_f)} graylog: {glres.get('hits').get('total').get('value')}')
				if len(defenderdata.get("Results")) > 0:
					print(f'{Fore.LIGHTBLUE_EX}defender found {Fore.YELLOW}{len(defenderdata.get("Results"))} for {Fore.CYAN}{addr}')
					results = defenderdata.get('Results')
					for res in results[:args.maxoutput]:
						print(f"{Fore.CYAN}   {res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} ")
				if len(azuredata) > 0:
					print(f'{Fore.LIGHTBLUE_EX}azure found {Fore.YELLOW}{len(azuredata)}')
					for logentry in azuredata[:args.maxoutput]:
						timest = logentry.get('TimeGenerated')
						status = json.loads(logentry.get('Status'))
						print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")
				if len(azuredata_f) > 0:
					print(f'{Fore.LIGHTBLUE_EX}azure failed signins found {Fore.YELLOW}{len(azuredata_f)}')
					for logentry in azuredata_f[:args.maxoutput]:
						timest = logentry.get('TimeGenerated')
						status = json.loads(logentry.get('Status'))
						print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")

	if args.ftgd_blk and args.graylog:
		searchquery = 'eventtype:ftgd_blk'
		try:
			results = await graylog_search(query=searchquery, range=86400)
		except ApiException as e:
			logger.warning(f'graylog search error: {e}')
			raise e
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			results = None
		if results:
			ipaddres_set = set([k.get('message').get('dstip') for k in results.get('hits').get('hits')])
			print(f'{Fore.LIGHTBLUE_EX}[2] graylog results:{Fore.YELLOW} {results.get('hits').get('total').get('value')} {Fore.LIGHTBLUE_EX}ipaddres_set:{Fore.YELLOW} {len(ipaddres_set)}')
			token = await get_aad_token()
			indicators = await get_indicators(token, args.host)
			for addr in ipaddres_set:
				print(f'{Fore.LIGHTBLUE_EX}serching logs for {Fore.CYAN}{addr}')
				[print(f'{Fore.CYAN}   indicator for {addr} found: {k}') for k in indicators if addr in str(k.values())]

				maxdays=1
				limit=100
				query = f"""let ip = "{addr}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """

				defenderdata = await search_devicenetworkevents(token, query)
				azuredata = await get_azure_signinlogs(addr)
				azuredata_f = await get_azure_signinlogs_failed(addr)
				# glq = f'srcip:{addr} OR dstip:{addr} OR remip:{addr}'
				glres = await graylog_search_ip(ip_address=addr, range=86400)
				# print(f'defender found {len(defenderdata.get("Results"))} azure found {len(azuredata)} graylog found {glres.total_results}')
				if glres.get('hits').get('total').get('value') > 0:
					print(f'{Fore.LIGHTBLUE_EX}[3] graylog results:{Fore.YELLOW} {glres.get('hits').get('total').get('value')}')
					for res in glres.get('hits').get('hits')[:args.maxoutput]:
						print(f"{Fore.CYAN}   {res_msg.get('timestamp')} {res_msg.get('msg')} {res_msg.get('action')} {res_msg.get('srcip')} {res_msg.get('dstip')} {res_msg.get('url')}")
				if len(defenderdata.get("Results")) > 0:
					print(f'{Fore.LIGHTBLUE_EX}defender found {Fore.YELLOW} {len(defenderdata.get("Results"))} {Fore.LIGHTBLUE_EX}for{Fore.CYAN} {addr}')
					results = defenderdata.get('Results')
					for res in results[:args.maxoutput]:
						print(f"{Fore.CYAN}   {res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} ")
				if len(azuredata) > 0:
					print(f'{Fore.LIGHTBLUE_EX} azure found {Fore.YELLOW} {len(azuredata)}')
					for logentry in azuredata[:args.maxoutput]:
						timest = logentry.get('TimeGenerated')
						status = json.loads(logentry.get('Status'))
						print(f"   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")
				if len(azuredata_f) > 0:
					print(f'{Fore.LIGHTBLUE_EX}azure failed signins found {Fore.YELLOW}{len(azuredata_f)}')
					for logentry in azuredata_f[:args.maxoutput]:
						timest = logentry.get('TimeGenerated')
						status = json.loads(logentry.get('Status'))
						print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")

	if args.azure:
		azuredata = await get_azure_signinlogs(args.host)
		if args.debug:
			logger.debug(f'azure signinlogs: {len(azuredata)}')
		if len(azuredata) >= 1:
			print(f'{Fore.LIGHTBLUE_EX}azure signinlogs:{Fore.GREEN}{len(azuredata)}')
			if len(azuredata) > 0:
				for logentry in azuredata[:args.maxoutput]:
					timest = logentry.get('TimeGenerated')
					status = json.loads(logentry.get('Status'))
					print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")
			else:
				print(f'{Fore.YELLOW}no azure data for {Fore.GREEN}{args.host}{Style.RESET_ALL}')

	if args.defender:
		try:
			token = await get_aad_token()
		except Exception as e:
			logger.error(e)
			os._exit(-1)
		if token:
			try:
				indicators = await get_indicators(token, args.host)
			except (DefenderException, TokenException) as e:
				logger.error(e)
				os._exit(-1)
			# if len([k for k in indicators if k.get('indicatorValue') == args.host]) <= 1:
			if len([k for k in indicators if args.host in str(k.values())]) >= 1:
				indx = [k for k in indicators if k.get('indicatorValue') == args.host]
				for ind in indx:
					print(f'{Fore.RED}indicator found: {Fore.GREEN} {ind.get("title")} {ind.get("description")} {Fore.LIGHTBLUE_EX}type: {ind.get("indicatorType")} action: {ind.get("action")} {Fore.LIGHTGREEN_EX} created by: {ind.get("createdBy")}')
			else:
				print(f'{Fore.YELLOW}no indicator found for {Fore.GREEN}{args.host}{Style.RESET_ALL}')
			try:
				maxdays=1
				limit=100
				query = f"""let ip = "{args.host}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """
				defenderdata = await search_devicenetworkevents(token, query)
				if len(defenderdata.get('Results')) >= 1:
					print(f"{Fore.BLUE}defender results:{Fore.GREEN} {len(defenderdata.get('Results'))}")
					results = defenderdata.get('Results')
					for res in results[:args.maxoutput]:
						print(f"{Fore.LIGHTBLUE_EX}{'':2} {res.get('Timestamp')}\n     {Fore.CYAN}device: {res.get('DeviceName')} user: {res.get('InitiatingProcessAccountName')} remip: {res.get('RemoteIP')}:{res.get('RemotePort')} localip: {res.get('LocalIP')} action: {res.get('ActionType')} \n     remoteurl: {res.get('RemoteUrl')} upn:{res.get('InitiatingProcessAccountUpn')} {Style.RESET_ALL}")
				else:
					print(f'{Fore.YELLOW}no defender results for {Fore.GREEN}{args.host}{Style.RESET_ALL}')
			except (DefenderException, TokenException) as e:
				logger.error(e)
				os._exit(-1)
			# print(f'results: {results}')

if __name__ == '__main__':
	vtinfo = None
	abuseipdbdata = None
	parser, args = get_args()
	try:
		asyncio.run(main(args))
	except KeyboardInterrupt as e:
		logger.error(f'mainerror: {e} {type(e)}')
	except ValueError as e:
		logger.error(f'mainerror: {e} {type(e)}')
	except TypeError as e:
		logger.error(f'mainerror: {e} {type(e)}')
	# except Exception as e:
	# 	logger.error(f'mainerror: {e} {type(e)}')
	print(f'{Style.RESET_ALL}')
