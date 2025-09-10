#!/usr/bin/env python3
import traceback
import asyncio
import pandas as pd
import os
import argparse
import json
from loguru import logger
from colorama import Fore, Style
from ipaddress import ip_address
from myglapi.rest import ApiException
from modules.virustotal import (get_virustotal_scanurls, get_virustotal_urlinfo, get_vt_ipinfo)
from modules.abuseipdb import get_abuseipdb_data
from modules.ipwhois import get_ipwhois
from modules.graylog import graylog_search, graylog_search_ip, print_graylog_summary
from modules.defender import (get_aad_token, search_devicenetworkevents, get_indicators, DefenderException, TokenException, search_remote_url)
from modules.azurelogs import get_azure_signinlogs, get_azure_signinlogs_failed
from modules.ip2loc import get_ip2loc_data
from modules.ipinfoio import get_ipinfo
from modules.urlscanio import search_urlscanio
from modules.crowdsec import get_crowdsec_data
import urllib3

urllib3.disable_warnings()


def get_args():
	parser = argparse.ArgumentParser(description="ip address lookup")
	parser.add_argument("-ip", "--host", help="ipaddress/host to lookup", type=str, metavar="ipaddr")
	parser.add_argument("--url", help="url to lookup", type=str, metavar="url")
	parser.add_argument("--vturl", help="virustotal url lookup", type=str)

	parser.add_argument("--ipwhois", help="ipwhois lookup", action="store_true", default=False)
	parser.add_argument("--skip_ipwhois", help="skip ipwhois lookup", action="store_true", default=False, dest="skip_ipwhois")

	parser.add_argument("-vt", "--virustotal", help="virustotal lookup", action="store_true", default=False, dest="virustotal")
	parser.add_argument("--skip_virustotal", help="skip virustotal lookup", action="store_true", default=False, dest="skip_virustotal")

	parser.add_argument("-ip2loc", "--ip2location", help="ip2location lookup", action="store_true", default=False, dest="ip2location")
	parser.add_argument("--skip_ip2location", help="skip ip2location lookup", action="store_true", default=False, dest="skip_ip2location")

	parser.add_argument("-ipinfo", "--ipinfo", help="ipinfo.io lookup", action="store_true", default=False, dest="ipinfoio")
	parser.add_argument("--skip_ipinfo", help="skip ipinfo.io lookup", action="store_true", default=False, dest="skip_ipinfo")

	parser.add_argument("--spam", help="spam lookup", action="store_true", default=False)
	parser.add_argument("--skip_spam", help="skip spam lookup", action="store_true", default=False, dest="skip_spam")

	parser.add_argument("-abip", "--abuseipdb", help="abuseipdb lookup", action="store_true", default=False, dest="abuseipdb")
	parser.add_argument("--skip_abuseipdb", help="skip abuseipdb lookup", action="store_true", default=False, dest="skip_abuseipdb")

	parser.add_argument("--crowdsec", help="crowdsec lookup", action="store_true", default=False, dest="crowdsec")
	parser.add_argument("--skip_crowdsec", help="skip crowdsec lookup", action="store_true", default=False, dest="skip_crowdsec")

	parser.add_argument("-us", "--urlscanio", help="urlscanio lookup", action="store_true", default=False, dest="urlscanio")
	parser.add_argument("--skip_urlscanio", help="skip urlscanio lookup", action="store_true", default=False, dest="skip_urlscanio")

	parser.add_argument("--graylog", help="search in graylog", action="store_true", default=False, dest="graylog")
	parser.add_argument("--skip_graylog", help="skip graylog search", action="store_true", default=False, dest="skip_graylog")

	parser.add_argument("--ftgd_blk", help="get ftgd_blk from graylog", action="store_true", default=False, dest="ftgd_blk")

	parser.add_argument("--sslvpnloginfail", help="get sslvpnloginfail from graylog", action="store_true", default=False, dest="sslvpnloginfail")

	parser.add_argument("-def", "--defender", help="search in defender", action="store_true", default=False, dest="defender")
	parser.add_argument("--skip_defender", help="skip defender search", action="store_true", default=False, dest="skip_defender")

	parser.add_argument("-az", "--azure", help="search azurelogs", action="store_true", default=False, dest="azure")
	parser.add_argument("--skip_azure", help="skip azurelogs search", action="store_true", default=False, dest="skip_azure")

	parser.add_argument("--maxoutput", help="limit output", default=10, type=int)
	parser.add_argument("--all", help="use all lookups", action="store_true", default=False)
	parser.add_argument("--debug", help="debug", action="store_true", default=False)
	args = parser.parse_args()
	return parser, args


async def main(args):
	if args.all:
		args.crowdsec = True
		args.ipwhois = True
		args.virustotal = True
		args.abuseipdb = True
		args.spam = True
		args.defender = True
		args.graylog = True
		args.azure = True
		args.urlscanio = True
		args.ip2location = True
		args.ipinfoio = True
		
	if args.skip_urlscanio:
		args.urlscanio = False
	if args.skip_ipinfo:
		args.ipinfoio = False
	if args.skip_spam:
		args.spam = False
	if args.skip_abuseipdb:
		args.abuseipdb = False
	if args.skip_azure:
		args.azure = False
	if args.skip_defender:
		args.defender = False
	if args.skip_graylog:
		args.graylog = False
	if args.skip_virustotal:
		args.virustotal = False
	if args.skip_ipwhois:
		args.ipwhois = False
	if args.skip_crowdsec:
		args.crowdsec = False
	if args.skip_ip2location:
		args.ip2location = False
	try:
		args.ipaddress = ip_address(args.host).exploded
	except ValueError as e:
		logger.warning(f"[!] {e} {type(e)} for address {args.host}")
		return

	if args.ipinfoio:
		# ipinfo.io lookup for {Fore.CYAN}{args.host} ipaddress: {ipaddress}')
		if args.debug:
			logger.debug(f"ipinfo.io lookup for {args.host} ipaddress: {args.ipaddress}")
		ipinfodata = await get_ipinfo(args)
		if ipinfodata:
			print(f"{Fore.LIGHTBLUE_EX}ipinfo.io data: {Fore.CYAN}{ipinfodata.get('country')} {ipinfodata.get('region')} {ipinfodata.get('city')} {ipinfodata.get('loc')} {ipinfodata.get('postal')} {ipinfodata.get('timezone')} org: {ipinfodata.get('org')}")
		else:
			logger.warning(f"no ipinfo.io data for {args.host} ipaddress: {args.ipaddress}")

	if args.ip2location:
		# ip2location lookup for {Fore.CYAN}{args.host} ipaddress: {ipaddress}')
		if args.debug:
			logger.debug(f"ip2location lookup for {args.host} ipaddress: {args.ipaddress}")
		ip2locdata = await get_ip2loc_data(args)
		if ip2locdata:
			print(f"{Fore.LIGHTBLUE_EX}ip2location data: {Fore.CYAN}{ip2locdata.get('country_code')} {ip2locdata.get('country_name')} {ip2locdata.get('region_name')} {ip2locdata.get('city_name')} {ip2locdata.get('latitude')}, {ip2locdata.get('longitude')} {ip2locdata.get('zip_code')} {ip2locdata.get('time_zone')} asn: {ip2locdata.get('asn')} as: {ip2locdata.get('as')}")
		else:
			logger.warning(f"no ip2location data for {args.host} ipaddress: {args.ipaddress}")
	if args.url:
		# search logs for remoteurl
		infourl = await get_virustotal_scanurls(args.url)
		vturlinfo = await get_virustotal_urlinfo(infourl)
		vt_url_resultdata = vturlinfo.get("data").get("attributes").get("results")
		defenderdata = {}
		try:
			token = await get_aad_token()
			defenderdata = await search_remote_url(args.url, token, limit=100, maxdays=3)
		except (DefenderException, TokenException) as e:
			logger.error(f'[!] Error getting defender data: {e} {type(e)} for url {args.url}')
			if args.debug:
				logger.error(traceback.format_exc())
			os._exit(-1)
		finally:
			print(f"{Fore.LIGHTBLUE_EX}vt url info  {Fore.CYAN} {len(vt_url_resultdata)}:{Fore.YELLOW} {vturlinfo.get('data').get('attributes').get('stats')}{Style.RESET_ALL}")
			for vendor in vt_url_resultdata:
				if vt_url_resultdata.get(vendor).get("category") == "malicious":
					print(f"{Fore.CYAN}   Vendor: {vendor} result: {vt_url_resultdata.get(vendor).get('result')} method: {vt_url_resultdata.get(vendor).get('method')} {Style.RESET_ALL}")
			print(f"{Fore.LIGHTBLUE_EX}defender data:{Fore.YELLOW} {len(defenderdata.get("Results", []))} {Style.RESET_ALL}")
			if len(defenderdata.get("Results", [])) >= 1:
				results = defenderdata.get("Results", [])
				for res in results[: args.maxoutput]:
					print(f"{Fore.CYAN}   {res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} {Style.RESET_ALL}")

	if args.urlscanio:
		try:
			urlscandata = await search_urlscanio(args.host)
			if urlscandata:
				print(f'{Fore.LIGHTBLUE_EX}urlscanio {Fore.LIGHTBLACK_EX}results:{Fore.YELLOW} {urlscandata.get("total")} ')
				for res in urlscandata.get("results"):
					print(f"{Fore.CYAN} time: {res.get('task').get('time')} vis: {res.get('task').get('visibility')} url: {res.get('task').get('url')} ")
			else:
				logger.warning(f"no urlscanio data for {args.host} urlscandata: {urlscandata}")
		except Exception as e:
			logger.error(f"unhandled {type(e)} {e}")

	if args.vturl:
		infourl = await get_virustotal_scanurls(args.vturl)
		print(f"{Fore.LIGHTBLUE_EX}getting info from vt url:{Fore.CYAN} {infourl}")
		vturlinfo = await get_virustotal_urlinfo(infourl)
		vt_url_resultdata = vturlinfo.get("data").get("attributes").get("results")
		print(f"{Fore.BLUE}vt url info:  {Fore.GREEN}{len(vt_url_resultdata)}: {vturlinfo.get('data').get('attributes').get('stats')}")
		for vendor in vt_url_resultdata:
			if vt_url_resultdata.get(vendor).get("category") == "malicious":
				print(f"{Fore.BLUE}   Vendor: {vendor} {Fore.CYAN}result: {vt_url_resultdata.get(vendor).get('result')} method: {vt_url_resultdata.get(vendor).get('method')} ")

	if args.ipwhois and args.ipaddress:
		# ipwhois lookup for {Fore.CYAN}{args.host} ipaddress: {ipaddress}')
		ipaddress = ip_address(args.host)
		if ipaddress.is_global:
			whois_info = await get_ipwhois(args)
			print(f"{Fore.LIGHTBLUE_EX}whois\n\t{Fore.CYAN} {whois_info}")
		elif ipaddress.is_private:
			print(f"{Fore.YELLOW}private address: {ipaddress}")

	if args.virustotal:
		vtinfo = {}
		vtinfo = await get_vt_ipinfo(args)
		if vtinfo:
			last_analysis_stats = vtinfo.get("last_analysis_stats", {})
			last_analysis_results = vtinfo.get("last_analysis_results", {})
			as_owner = vtinfo.get("as_owner", "None")
			# vt_aso = vtinfo.as_owner
			total_votes = vtinfo.get("total_votes", {})
			as_owner = {}
			total_votes = {}
			suspicious = last_analysis_stats.get('suspicious')  # type: ignore
			malicious = last_analysis_stats.get('malicious')  # type: ignore
			malicious += int(total_votes.get("malicious", 0))
			if malicious+suspicious > 0:
				vtforecolor = Fore.RED
			else:
				vtforecolor = Fore.GREEN
			print(f"{Fore.LIGHTBLUE_EX}vt\t{args.host} asowner:{Fore.CYAN} {as_owner} vtvotes: {vtforecolor} malicious: {malicious} suspicious: {suspicious}  ")
			for vendor in last_analysis_results:  # type: ignore
				if last_analysis_results.get(vendor).get("category") in ('suspicious', "malicious"):  # type: ignore
					print(f"{Fore.BLUE}\t{vendor} {Fore.CYAN} result: {last_analysis_results.get(vendor).get('result')} {last_analysis_results.get(vendor).get('method')} ")  # type: ignore

	if args.abuseipdb:
		abuseipdbdata = await get_abuseipdb_data(args.host)
		if abuseipdbdata:
			print(f'{Fore.LIGHTBLUE_EX}abuseipdb Reports:{Fore.CYAN} {abuseipdbdata.get("data").get("totalReports")} abuseConfidenceScore: {abuseipdbdata.get("data").get("abuseConfidenceScore")} isp: {abuseipdbdata.get("data").get("isp")} country: {abuseipdbdata.get("data").get("countryCode")} hostname:{Fore.CYAN} {abuseipdbdata.get("data").get("hostnames")} domain: {abuseipdbdata.get("data").get("domain")} tor: {abuseipdbdata.get("data").get("isTor")}')

	if args.crowdsec:
		crowdsecdata = await get_crowdsec_data(args)
		if crowdsecdata:
			print(f'{Fore.LIGHTBLUE_EX}crowdsec Reports:{Fore.CYAN} {crowdsecdata.get("reputation")} confidence: {crowdsecdata.get("confidence")}')

	if args.graylog:
		try:
			if args.debug:
				logger.debug(f"searching graylog for {args.host}")
			results = await graylog_search_ip(args.host, range=86400)
		except ApiException as e:
			logger.warning(f"graylog search error: {e}")
			results = None
		except TypeError as e:
			logger.error(f"graylog search error: {e} {type(e)}")
			if args.debug:
				logger.error(traceback.format_exc())
			results = None
		except Exception as e:
			logger.error(f"graylog search error: {e} {type(e)}")
			results = None
		if results:
			print_graylog_summary(results)
			df = pd.DataFrame([k["_source"] for k in results.get("hits").get("hits")])
			# Additional detailed analysis
			if results.get("hits").get("total").get("value") > 0:
				print(f"\n{Fore.LIGHTBLUE_EX}=== Detailed Analysis ==={Style.RESET_ALL}")

				# Citrix specific analysis
				if "citrixtype" in df.columns or "type" in df.columns:
					if "citrixtype" in df.columns or (df["type"] == "citrixtype").any():
						print(f"{Fore.LIGHTBLUE_EX}Citrix NetScaler Data Analysis:")

						# Analyze traffic patterns
						if "Total_bytes_recv" in df.columns and "Total_bytes_send" in df.columns:
							total_recv = df["Total_bytes_recv"].sum()
							total_sent = df["Total_bytes_send"].sum()
							print(f"  {Fore.CYAN}Total Traffic - Received: {Fore.YELLOW}{total_recv:,} bytes {Fore.CYAN}Sent: {Fore.YELLOW}{total_sent:,} bytes")

						# Top destinations
						if "Destination" in df.columns:
							top_destinations = df["Destination"].value_counts().head(10)
							print(f"  {Fore.CYAN}Top Destinations:")
							for dest, count in top_destinations.items():
								print(f"    {Fore.YELLOW}{dest}: {count}")

						# Virtual server analysis
						if "Vserver" in df.columns:
							vservers = df["Vserver"].value_counts().head(5)
							print(f"  {Fore.CYAN}Virtual Servers:")
							for vserver, count in vservers.items():
								print(f"    {Fore.YELLOW}{vserver}: {count}")

						# Source and destination address patterns
						if "SourceAddress" in df.columns and "DestinationAddress" in df.columns:
							unique_sources = df["SourceAddress"].nunique()
							unique_dests = df["DestinationAddress"].nunique()
							print(f"  {Fore.CYAN}Connection Diversity - Unique Sources: {Fore.YELLOW}{unique_sources} {Fore.CYAN}Unique Destinations: {Fore.YELLOW}{unique_dests}")

				# Time-based analysis
				if "timestamp" in df.columns:
					df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
					hourly_activity = df["hour"].value_counts().sort_index()
					print(f"  {Fore.CYAN}Hourly Activity Distribution:")
					for hour, count in hourly_activity.head(10).items():
						print(f"    {Fore.YELLOW}Hour {hour:02d}: {count} events")

				print(f"{Fore.GREEN}[1] graylog results:{Fore.LIGHTGREEN_EX} {results.get('hits').get('total').get('value')}")
				for res in results.get("hits").get("hits")[: args.maxoutput]:
					res_idx = res.get("_index")
					res_msg = res.get("_source")
					if "msgraph" in res_idx:
						print(f"{Fore.YELLOW} {res_idx} {res_msg.get('gl2_receive_timestamp')} {res_msg.get('RequestMethod')} {res_msg.get('displayName')} {res_msg.get('IpAddress')} {res_msg.get('dstip')} {res_msg.get('RequestUri')}")
					else:
						print(f"{Fore.YELLOW}{res_idx} {Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} country:{res_msg.get('srccountry')} - {res_msg.get('dstcountry')} {Fore.CYAN} action:{res_msg.get('action')} srcip:{res_msg.get('srcip')} dstip:{res_msg.get('dstip')} transip:{res_msg.get('transip')} service: {res_msg.get('service')} url:{res_msg.get('url')} srcname:{res_msg.get('srcname')}")
					# print(f"   {Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} srccountry:{res_msg.get('srccountry')} {Fore.CYAN} action:{res_msg.get('action')} srcip:{res_msg.get('srcip')} dstip:{res_msg.get('dstip')} service: {res_msg.get('service')} url:{res_msg.get('url')}")
				if "msg" in df.columns and "srcip" in df.columns:
					print(f"{Fore.LIGHTBLUE_EX}top 15 actions by srcip:")
					try:
						print(df.groupby(["action", "msg", "srcip"])["msg"].agg(["count"]).sort_values(by="count", ascending=False).head(15))
					except KeyError as e:
						logger.error(f"KeyError: {e} - check graylog data structure. {df.columns}")

					print(f"{Fore.LIGHTBLUE_EX}top 15 actions by dstip:")
					try:
						print(df.groupby(["action", "msg", "dstip"])["msg"].agg(["count"]).sort_values(by="count", ascending=False).head(15))
					except KeyError as e:
						logger.error(f"KeyError: {e} - check graylog data structure. {df.columns}")

					print(f"{Fore.LIGHTBLUE_EX}top 15 actions by type and ip:")
					print(df.groupby(["action", "type", "subtype", "srcip", "dstip"])["timestamp"].agg(["count"]).sort_values(by="count", ascending=False).head(15))
					print(df.groupby(["action", "srcip"])["srcip"].agg(["count"]).sort_values(by="count", ascending=False).head(15))
				if "citrixtype" in df.columns or "request" in df.columns:
					print(f"{Fore.LIGHTBLUE_EX}Citrix data found - processing citrixtype column")
					# print(df.groupby(['action', 'srcip'])['srcip'].agg(['count']).sort_values(by='count', ascending=False).head(15))
				if "msg" in df.columns and "remip" in df.columns:
					print(f"{Fore.LIGHTBLUE_EX}top 15 actions by remip:")
					try:
						print(df.groupby(["action", "msg", "remip", "username"])["msg"].agg(["count"]).sort_values(by="count", ascending=False).head(15))
					except KeyError as e:
						logger.error(f"KeyError: {e} - check graylog data structure. {df.columns}")
			else:
				print(f"{Fore.YELLOW}no graylog data ({results.get('hits').get('total').get('value')}) for {Fore.GREEN}{args.host}{Style.RESET_ALL}")
		else:
			print(f"{Fore.YELLOW}no graylog results for {Fore.GREEN}{args.host}{Style.RESET_ALL}")

	if args.sslvpnloginfail and args.graylog:
		searchquery = "action:ssl-login-fail"
		res_msg = {}
		try:
			results = await graylog_search(query=searchquery, range=86400)
		except ApiException as e:
			logger.warning(f"graylog search error: {e}")
			results = None
		except Exception as e:
			logger.error(f"graylog search error: {e} {type(e)}")
			results = None
		if results:
			ipaddres_set = set([k.get("message").get("remip") for k in results.get("hits").get("hits")])  # type: ignore
			print(f"{Fore.LIGHTBLUE_EX}graylog sslvpnloginfail {Fore.CYAN}results: {results.get('hits').get('total').get('value')} ipaddres_set: {len(ipaddres_set)}")  # type: ignore
			for res in results.get("hits").get("hits")[: args.maxoutput]:  # type: ignore
				print(f"{Fore.YELLOW}   {res_msg.get('timestamp')} {res_msg.get('msg')} {res_msg.get('action')} {res_msg.get('user')} {res_msg.get('remip')} {res_msg.get('source')}")
			try:
				token = await get_aad_token()
			except TokenException as e:
				logger.error(f"TokenException: {e} {type(e)}")
				return
			for addr in ipaddres_set:
				print(f"{Fore.LIGHTBLUE_EX}serching logs for {Fore.YELLOW}{addr}")
				if args.debug:
					logger.debug(f"searching defender for {addr}")
				maxdays = 1
				limit = 100
				query = f"""let ip = "{addr}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """
				defenderdata = await search_devicenetworkevents(token, query)
				if args.debug:
					logger.debug(f'defender returned {len(defenderdata.get("Results"))} ... searching azure logs for {addr}')
				try:
					azuredata = await get_azure_signinlogs(args)
				except Exception as e:
					logger.error(f"azure logs error: {e} {type(e)} for {addr}")
					azuredata = []
				if args.debug:
					logger.debug(f"azure logs returned {len(azuredata)} ... searching azure failed signin logs for {addr}")
				azuredata_f = await get_azure_signinlogs_failed(args)
				if args.debug:
					logger.debug(f"azure failed signin logs returned {len(azuredata_f)} ... searching graylog for {addr}")
				glres = await graylog_search_ip(addr, range=86400)
				if args.debug:
					logger.debug(f'graylog search returned {glres.get("hits").get("total").get("value")} results for {addr}')  # type: ignore
				print(f'{Fore.CYAN}   results for {addr} defender: {len(defenderdata.get("Results"))} azure: {len(azuredata)} azure failed: {len(azuredata_f)} graylog: {glres.get('hits').get('total').get('value')}')  # type: ignore
				if len(defenderdata.get("Results")) > 0:
					print(f'{Fore.LIGHTBLUE_EX}defender found {Fore.YELLOW}{len(defenderdata.get("Results"))} for {Fore.CYAN}{addr}')
					results = defenderdata.get("Results")
					for res in results[: args.maxoutput]:
						print(f"{Fore.CYAN}   {res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} ")
				if len(azuredata) > 0:
					print(f"{Fore.LIGHTBLUE_EX}azure found {Fore.YELLOW}{len(azuredata)}")
					for logentry in azuredata[: args.maxoutput]:
						timest = logentry.get("TimeGenerated")
						status = json.loads(logentry.get("Status"))  # type: ignore
						print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")  # type: ignore
				if len(azuredata_f) > 0:
					print(f"{Fore.LIGHTBLUE_EX}azure failed signins found {Fore.YELLOW}{len(azuredata_f)}")
					for logentry in azuredata_f[: args.maxoutput]:
						timest = logentry.get("TimeGenerated")
						status = json.loads(logentry.get("Status"))  # type: ignore
						print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")  # type: ignore

	if args.ftgd_blk and args.graylog:
		searchquery = "eventtype:ftgd_blk"
		try:
			results = await graylog_search(query=searchquery, range=86400)
		except ApiException as e:
			logger.warning(f"graylog search error: {e}")
			raise e
		except Exception as e:
			logger.error(f"graylog search error: {e} {type(e)}")
			results = None
		if results:
			ipaddres_set = set([k.get("message").get("dstip") for k in results.get("hits").get("hits")])  # type: ignore
			print(f"{Fore.LIGHTBLUE_EX}[2] graylog results:{Fore.YELLOW} {results.get('hits').get('total').get('value')} {Fore.LIGHTBLUE_EX}ipaddres_set:{Fore.YELLOW} {len(ipaddres_set)}")  # type: ignore
			try:
				token = await get_aad_token()
			except TokenException as e:
				logger.error(f"TokenException: {e} {type(e)}")
				return
			indicators = await get_indicators(token, args.host)
			for addr in ipaddres_set:
				print(f"{Fore.LIGHTBLUE_EX}serching logs for {Fore.CYAN}{addr}")
				[print(f"{Fore.CYAN}   indicator for {addr} found: {k}") for k in indicators if addr in str(k.values())]  # type: ignore

				maxdays = 1
				limit = 100
				query = f"""let ip = "{addr}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """
				try:
					defenderdata = await search_devicenetworkevents(token, query)
					azuredata = await get_azure_signinlogs(args)
					azuredata_f = await get_azure_signinlogs_failed(args)
				except Exception as e:
					logger.error(f"error searching defender or azure logs: {e} {type(e)} for {addr}")
					if args.debug:
						logger.error(traceback.format_exc())
					defenderdata = {"Results": []}
					azuredata = []
					azuredata_f = []
				# glq = f'srcip:{addr} OR dstip:{addr} OR remip:{addr}'
				glres = await graylog_search_ip(ip_address=addr, range=86400)
				# print(f'defender found {len(defenderdata.get("Results"))} azure found {len(azuredata)} graylog found {glres.total_results}')
				if glres.get("hits").get("total").get("value") > 0:  # type: ignore
					print(f"{Fore.LIGHTBLUE_EX}[3] graylog results:{Fore.YELLOW} {glres.get('hits').get('total').get('value')}")  # type: ignore
					for res in glres.get("hits").get("hits")[: args.maxoutput]:  # type: ignore
						print(f"{Fore.CYAN}   {res_msg.get('timestamp')} {res_msg.get('msg')} {res_msg.get('action')} {res_msg.get('srcip')} {res_msg.get('dstip')} {res_msg.get('url')}")  # type: ignore
				if len(defenderdata.get("Results")) > 0:  # type: ignore
					print(f'{Fore.LIGHTBLUE_EX}defender found {Fore.YELLOW} {len(defenderdata.get("Results"))} {Fore.LIGHTBLUE_EX}for{Fore.CYAN} {addr}')  # type: ignore
					results = defenderdata.get("Results")
					for res in results[: args.maxoutput]:  # type: ignore
						print(f"{Fore.CYAN}   {res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} ")
				if len(azuredata) > 0:
					print(f"{Fore.LIGHTBLUE_EX} azure found {Fore.YELLOW} {len(azuredata)}")
					for logentry in azuredata[: args.maxoutput]:
						timest = logentry.get("TimeGenerated")
						status = json.loads(logentry.get("Status"))  # type: ignore
						print(f"   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")  # type: ignore
				if len(azuredata_f) > 0:
					print(f"{Fore.LIGHTBLUE_EX}azure failed signins found {Fore.YELLOW}{len(azuredata_f)}")
					for logentry in azuredata_f[: args.maxoutput]:
						timest = logentry.get("TimeGenerated")
						status = json.loads(logentry.get("Status"))  # type: ignore
						print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")  # type: ignore

	if args.azure:
		try:
			azuredata = await get_azure_signinlogs(args)
		except Exception as e:
			logger.error(f"azure logs error: {e} {type(e)} for {args.host}")
			azuredata = []
			if args.debug:
				logger.error(traceback.format_exc())
		if args.debug:
			logger.debug(f"azure signinlogs: {len(azuredata)}")
		if len(azuredata) >= 1:
			print(f"{Fore.LIGHTBLUE_EX}azure signinlogs:{Fore.GREEN}{len(azuredata)}")
			if len(azuredata) > 0:
				for logentry in azuredata[: args.maxoutput]:
					timest = logentry.get("TimeGenerated")
					status = json.loads(logentry.get("Status"))  # type: ignore
					print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} mfa: {logentry.get('MfaDetail')}")  # type: ignore
			else:
				print(
					f"{Fore.YELLOW}no azure data for {Fore.GREEN}{args.host}{Style.RESET_ALL}"
				)

	if args.defender:
		try:
			token = await get_aad_token()
		except TokenException as e:
			logger.warning(f'TokenException: {e} {type(e)}')
			token = None
		except Exception as e:
			logger.error(f'error getting aad token: {e} {type(e)}')
			if args.debug:
				logger.error(traceback.format_exc())
			token = None
		if token:
			try:
				indicators = await get_indicators(token, args.host)
			except (DefenderException, TokenException) as e:
				logger.error(e)
				os._exit(-1)
			# if len([k for k in indicators if k.get('indicatorValue') == args.host]) <= 1:
			if len([k for k in indicators if args.host in str(k.values())]) >= 1:  # type: ignore
				indx = [k for k in indicators if k.get("indicatorValue") == args.host]  # type: ignore
				for ind in indx:
					print(f'{Fore.RED}indicator found: {Fore.GREEN} {ind.get("title")} {ind.get("description")} {Fore.LIGHTBLUE_EX}type: {ind.get("indicatorType")} action: {ind.get("action")} {Fore.LIGHTGREEN_EX} created by: {ind.get("createdBy")}')
			else:
				print(f"{Fore.YELLOW}no indicator found for {Fore.GREEN}{args.host}{Style.RESET_ALL}")
			try:
				maxdays = 1
				limit = 100
				query = f"""let ip = "{args.host}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """
				defenderdata = await search_devicenetworkevents(token, query)
				if len(defenderdata.get("Results")) >= 1:
					print(f"{Fore.BLUE}defender results:{Fore.GREEN} {len(defenderdata.get('Results'))}")
					results = defenderdata.get("Results")
					for res in results[: args.maxoutput]:
						print(f"{Fore.LIGHTBLUE_EX}{'':2} {res.get('Timestamp')}\n     {Fore.CYAN}device: {res.get('DeviceName')} user: {res.get('InitiatingProcessAccountName')} remip: {res.get('RemoteIP')}:{res.get('RemotePort')} localip: {res.get('LocalIP')} action: {res.get('ActionType')} \n     remoteurl: {res.get('RemoteUrl')} upn:{res.get('InitiatingProcessAccountUpn')} {Style.RESET_ALL}")
				else:
					print(f"{Fore.YELLOW}no defender results for {Fore.GREEN}{args.host}{Style.RESET_ALL}")
			except (DefenderException, TokenException) as e:
				logger.error(e)
				os._exit(-1)
			# print(f'results: {results}')


if __name__ == "__main__":
	vtinfo = None
	abuseipdbdata = None
	parser, args = get_args()
	try:
		asyncio.run(main(args))
	except KeyboardInterrupt as e:
		logger.error(f"mainerror: {e} {type(e)}")
	except ValueError as e:
		logger.error(f"mainerror: {e} {type(e)}")
		logger.error(traceback.format_exc())
	except TypeError as e:
		logger.error(f"mainerror: {e} {type(e)}")
	# except Exception as e:
	# 	logger.error(f'mainerror: {e} {type(e)}')
	print(f"{Style.RESET_ALL}")
