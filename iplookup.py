#!/usr/bin/env python3
import traceback
import asyncio
import os
import argparse
import json
from loguru import logger
from colorama import Fore, Style
from ipaddress import ip_address
from opensearchpy.exceptions import RequestError
from myglapi.rest import ApiException
from modules.virustotal import (get_virustotal_scanurls, get_virustotal_urlinfo, get_vt_ipinfo)
from modules.abuseipdb import get_abuseipdb_data
from modules.ipwhois import get_ipwhois
from modules.graylog import graylog_search, graylog_search_ip, print_graylog_summary, print_graylog_data
from modules.defender import (get_aad_token, search_devicenetworkevents, get_indicators, DefenderException, TokenException, search_remote_url)
from modules.azurelogs import get_azure_signinlogs, get_azure_signinlogs_failed
from modules.ip2loc import get_ip2loc_data
from modules.ipinfoio import get_ipinfo
from modules.urlscanio import search_urlscanio
from modules.crowdsec import get_crowdsec_data
from modules.alienvault import get_alienvault_data
from modules.pulsedrive import get_pulsedrive_data
from modules.dnsdumpster import get_dnsdumpster

import urllib3

urllib3.disable_warnings()

# todo
# add https://analytics.dugganusa.com/api/v1/stix-feed
# https://analytics.dugganusa.com/api/v1/stix-feed/v2
# curl -s https://analytics.dugganusa.com/api/v1/stix-feed |   jq -r '.objects[] | select(.type=="indicator") | .pattern' |   grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u
# add https://cleantalk.org/blacklists/34.149.87.45
# add https://www.netify.ai/resources/ips/34.149.87.45
# add https://www.criminalip.io/asset/report/34.149.87.45
# add https://viewdns.info/
# add https://cleantalk.org
# add https://www.malwareurl.com
# finish https://urlhaus.abuse.ch/api/
# finish https://dnsdumpster.com/

def get_args():
	parser = argparse.ArgumentParser(description="ip address lookup")
	parser.add_argument("-ip", help="ipaddress/host to lookup", type=str, metavar="ipaddr")
	parser.add_argument("-ipfile", help="filename containing ipaddresses/hosts to lookup", type=str, metavar="filename")
	parser.add_argument("-ips", help="list of ipaddress/host to lookup", type=list, default=[], metavar="ipaddrlist", nargs='+')
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
	parser.add_argument("--dumpabusedata", help="dump abuseipdb data", action="store_true", default=False, dest="dumpabusedata")

	parser.add_argument("--crowdsec", help="crowdsec lookup", action="store_true", default=False, dest="crowdsec")
	parser.add_argument("--skip_crowdsec", help="skip crowdsec lookup", action="store_true", default=False, dest="skip_crowdsec")

	parser.add_argument("-us", "--urlscanio", help="urlscanio lookup", action="store_true", default=False, dest="urlscanio")
	parser.add_argument("--dumpurlscandata", help="dump urlscan data", action="store_true", default=False, dest="dumpurlscandata")
	parser.add_argument("--skip_urlscanio", help="skip urlscanio lookup", action="store_true", default=False, dest="skip_urlscanio")

	parser.add_argument('-av', '--alienvault', help='alienvault lookup', action='store_true', default=False, dest='alienvault')
	parser.add_argument('--skip_alienvault', help='skip alienvault lookup', action='store_true', default=False, dest='skip_alienvault')

	parser.add_argument('-pv', '--pulsedrive', help='pulsedrive lookup', action='store_true', default=False, dest='pulsedrive')
	parser.add_argument('--skip_pulsedrive', help='skip pulsedrive lookup', action='store_true', default=False, dest='skip_pulsedrive')
	parser.add_argument('--dumppulsedrive', help='dump pulsedrive data', action='store_true', default=False, dest='dumppulsedrive')

	parser.add_argument("--dnsdumpster", help="dnsdumpster lookup", action="store_true", default=False, dest="dnsdumpster")
	parser.add_argument("--skip_dnsdumpster", help="skip dnsdumpster lookup", action="store_true", default=False, dest="skip_dnsdumpster")
	parser.add_argument("--dump_dnsdumpster", help="dump dnsdumpster data", action="store_true", default=False, dest="dump_dnsdumpster")

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
	parser.add_argument("--dumpall", help="full dump", action="store_true", default=False)
	parser.add_argument("--debug", help="debug", action="store_true", default=False)

	args = parser.parse_args()
	return parser, args

async def main(args):
	if args.ipfile:
		try:
			with open(args.ipfile, 'r') as f:
				file_ips = [line.strip() for line in f if line.strip() if line.count('.') == 3]
				args.ips.extend(file_ips)
			for ip in args.ips:
				try:
					ipaddress = ip_address(ip).exploded
				except ValueError as e:
					logger.warning(f"[!] {e} {type(e)} for address {ip}")
					raise e
				except Exception as e:
					logger.error(f"[!] unhandled {e} {type(e)} for address {ip}")
					raise e
				if args.debug:
					logger.debug(f"loaded {len(file_ips)} ipaddresses from {args.ipfile}")
		except Exception as e:
			logger.error(f"error reading ipfile {args.ipfile}: {e} {type(e)}")
			return
	elif args.ip:
		try:
			ipaddress = ip_address(args.ip).exploded
			args.ip = ipaddress
		except ValueError as e:
			logger.warning(f"[!] {e} {type(e)} for address {args.ip}")
			return
		except Exception as e:
			logger.error(f"[!] unhandled {e} {type(e)} for address {args.ip}")
			return
	elif args.ips:
		for ip_ in args.ips:
			ip = ''.join(ip_)
			try:                
				ipaddress = ip_address(''.join(ip)).exploded
			except ValueError as e:
				logger.warning(f"[!] {e} {type(e)} for address {ip}")
				raise e
			except Exception as e:
				logger.error(f"[!] unhandled {e} {type(e)} for address {ip}")
				raise e
	
	if args.all:
		args.dnsdumpster = True
		args.pulsedrive = True
		args.alienvault = True
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
	
	if args.skip_alienvault:
		args.alienvault = False
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
	if args.skip_pulsedrive:
		args.pulsedrive = False
	
	if args.dumpall:
		args.dumppulsedrive = True
		args.dumpurlscandata = True
		args.dumpabusedata = True
		args.dump_dnsdumpster = True

	# Create a list to hold all async tasks
	tasks = []
	results = {}

	# Helper function to run module and store results
	async def run_module(module_name, coro):
		try:
			result = await coro
			results[module_name] = result
			return result
		except Exception as e:
			logger.error(f"Error in {module_name}: {e}")
			results[module_name] = None
			return None

	# Add tasks based on enabled modules
	if args.dnsdumpster:
		pass  # tasks.append(run_module("dnsdumpster", get_dnsdumpster(args)))  # todo finish

	if args.pulsedrive:
		tasks.append(run_module("pulsedrive", get_pulsedrive_data(args)))
	
	if args.alienvault:
		tasks.append(run_module("alienvault", get_alienvault_data(args)))
	
	if args.ipinfoio:
		if args.ips:
			for ipaddr in args.ips:
				args_copy = argparse.Namespace(**vars(args))
				args_copy.ip = ''.join(ipaddr)
				tasks.append(run_module(f"ipinfoio_{ipaddr}", get_ipinfo(args_copy)))
		elif args.ip:
			tasks.append(run_module("ipinfoio", get_ipinfo(args)))
	
	if args.ip2location:
		if args.ips:
			for ipaddr in args.ips:
				args_copy = argparse.Namespace(**vars(args))
				args_copy.ip = ''.join(ipaddr)
				tasks.append(run_module(f"ip2location_{ipaddr}", get_ip2loc_data(args_copy)))
		elif args.ip:
			tasks.append(run_module("ip2location", get_ip2loc_data(args)))
	
	if args.url:
		# URL-specific tasks
		infourl_task = run_module("virustotal_scanurls", get_virustotal_scanurls(args.url))
		tasks.append(infourl_task)
		
		# Run this one first to get the URL for the next task
		infourl = await infourl_task
		if infourl:
			tasks.append(run_module("virustotal_urlinfo", get_virustotal_urlinfo(infourl)))
		
		# Defender URL search
		try:
			token = await get_aad_token()
			tasks.append(run_module("defender_url", search_remote_url(args.url, token, limit=100, maxdays=3)))
		except (DefenderException, TokenException) as e:
			logger.error(f'[!] Error getting defender data: {e} {type(e)} for url {args.url}')
			if args.debug:
				logger.error(traceback.format_exc())
	
	if args.urlscanio:
		tasks.append(run_module("urlscanio", search_urlscanio(args.ip)))
	
	if args.vturl:
		infourl_task = run_module("virustotal_scanurls_vturl", get_virustotal_scanurls(args.vturl))
		tasks.append(infourl_task)
		infourl = await infourl_task
		if infourl:
			tasks.append(run_module("virustotal_urlinfo_vturl", get_virustotal_urlinfo(infourl)))
	
	if args.ipwhois and args.ip:
		ipaddress = ip_address(args.ip)
		if ipaddress.is_global:
			tasks.append(run_module("ipwhois", get_ipwhois(args)))
		elif ipaddress.is_private:
			print(f"{Fore.YELLOW}private address: {ipaddress}")
	
	if args.virustotal:
		if args.ips:
			for ipaddr in args.ips:
				args_copy = argparse.Namespace(**vars(args))
				args_copy.ip = ''.join(ipaddr)
				tasks.append(run_module(f"virustotal_{ipaddr}", get_vt_ipinfo(args_copy)))
		elif args.ip:
			tasks.append(run_module("virustotal", get_vt_ipinfo(args)))
	
	if args.abuseipdb:
		tasks.append(run_module("abuseipdb", get_abuseipdb_data(args.ip)))
	
	if args.crowdsec:
		tasks.append(run_module("crowdsec", get_crowdsec_data(args)))
	
	if args.graylog:
		if args.ips:
			for ipaddr in args.ips:
				args_copy = argparse.Namespace(**vars(args))
				args_copy.ip = ''.join(ipaddr)
				tasks.append(run_module(f"graylog_{ipaddr}", graylog_search_ip(args_copy, range=86400)))
		elif args.ip:
			tasks.append(run_module("graylog", graylog_search_ip(args, range=86400)))
	
	if args.sslvpnloginfail and args.graylog:
		tasks.append(run_module("sslvpnloginfail", graylog_search(query="action:ssl-login-fail", range=86400)))
	
	if args.ftgd_blk and args.graylog:
		tasks.append(run_module("ftgd_blk", graylog_search(query="eventtype:ftgd_blk", range=86400)))
	
	if args.azure:
		tasks.append(run_module("azure", get_azure_signinlogs(args)))
	
	if args.defender:
		try:
			token = await get_aad_token()
			tasks.append(run_module("defender_indicators", get_indicators(token, args.ip)))
			
			maxdays = 1
			limit = 100
			query = f"""let ip = "{args.ip}";search in (DeviceNetworkEvents) Timestamp between (ago({maxdays}d) .. now()) and (LocalIP == ip or RemoteIP == ip) | take {limit} """
			tasks.append(run_module("defender_network", search_devicenetworkevents(token, query)))
		except (TokenException, DefenderException) as e:
			logger.error(f'Error getting defender token: {e}')
	
	# Run all tasks concurrently
	if tasks:
		await asyncio.gather(*tasks, return_exceptions=True)
	
	# Process and display results
	await process_results(results, args)

async def process_results(results, args):
	"""Process and display the results from all modules"""
	# dnsdumpster results
	if "dnsdumpster" in results and results["dnsdumpster"]:
		data = results["dnsdumpster"]
		print(f"{Fore.LIGHTBLUE_EX}dnsdumpster data for {args.ip}:{Style.RESET_ALL}")
		if args.dump_dnsdumpster:
			print(json.dumps(data, indent=2))
	# Pulsedrive results
	if "pulsedrive" in results and results["pulsedrive"]:
		data = results["pulsedrive"]
		for pulsedivedata in data:
			threats = pulsedivedata.get('threats')
			risk = pulsedivedata.get('risk')
			risk_color = Fore.GREEN
			if risk == 'low':
				risk_color = Fore.GREEN
			elif risk == 'medium':
				risk_color = Fore.YELLOW 
			elif risk == 'high':
				risk_color = Fore.RED
			print(f"{Fore.LIGHTBLUE_EX}pulsedrive: type: {pulsedivedata.get('type')} {risk_color}risk:{risk} feeds: {len(pulsedivedata.get('feeds'))} threats: {len(threats)}{Style.RESET_ALL}")
			if args.dumppulsedrive:
				for threat in threats:
					print(f"{Fore.CYAN} threat: {threat.get('name')} category: {threat.get('category')} risk: {threat.get('risk')} {Style.RESET_ALL}")
				for feed in pulsedivedata.get('feeds'):
					category = feed.get('category')
					cat_color = Fore.GREEN
					if category in ['malware', 'abuse', 'botnet', 'phishing']:
						cat_color = Fore.RED
					print(f"{Fore.CYAN} feed: {feed.get('name')} category: {cat_color}{category} {Style.RESET_ALL}")
	elif args.pulsedrive:
		logger.warning(f"no pulsedrive data for {args.ip}")
	
	# Alienvault results
	if "alienvault" in results and results["alienvault"]:
		data = results["alienvault"]
		for avdata in data:
			print(f"{Fore.LIGHTBLUE_EX}alienvault {avdata.get('indicator')} data: {Fore.CYAN}{avdata.get('pulse_info').get('count')} pulses{Style.RESET_ALL} country:{Fore.LIGHTRED_EX}{avdata.get('country_code')}{Style.RESET_ALL} reputation: {Fore.LIGHTGREEN_EX}{avdata.get('reputation')}{Style.RESET_ALL}")
			for pulse in avdata.get('pulse_info').get('pulses'):
				print(f"{Fore.CYAN} pulse: {pulse.get('name')} created: {pulse.get('created')} modified: {pulse.get('modified')} {Style.RESET_ALL}")
	elif args.alienvault:
		logger.warning(f"no alienvault data for {args.ip}")
	
	# IPInfo.io results
	for key in results:
		if key.startswith("ipinfoio"):
			ipinfodata = results[key]
			if ipinfodata:
				ipaddr = key.replace("ipinfoio_", "") if "_" in key else args.ip
				print(f"{Fore.LIGHTBLUE_EX}ipinfo.io data for {ipaddr}: {Fore.CYAN}{ipinfodata.get('country')} {ipinfodata.get('region')} {ipinfodata.get('city')} {ipinfodata.get('loc')} {ipinfodata.get('postal')} {ipinfodata.get('timezone')} org: {ipinfodata.get('org')}")
			elif args.ipinfoio:
				logger.warning(f"no ipinfo.io data for {args.ip}")
	
	# IP2Location results
	for key in results:
		if key.startswith("ip2location"):
			ip2locdata = results[key]
			if ip2locdata:
				ipaddr = key.replace("ip2location_", "") if "_" in key else args.ip
				print(f"{Fore.LIGHTBLUE_EX}ip2location data for {ipaddr}: {Fore.CYAN}{ip2locdata.get('country_code')} {ip2locdata.get('country_name')} {ip2locdata.get('region_name')} {ip2locdata.get('city_name')} {ip2locdata.get('latitude')}, {ip2locdata.get('longitude')} {ip2locdata.get('zip_code')} {ip2locdata.get('time_zone')} asn: {ip2locdata.get('asn')} as: {ip2locdata.get('as')}")
			elif args.ip2location:
				logger.warning(f"no ip2location data for {args.ip}")
	
	# URL-specific results
	if "virustotal_urlinfo" in results and results["virustotal_urlinfo"]:
		vturlinfo = results["virustotal_urlinfo"]
		vt_url_resultdata = vturlinfo.get("data", {}).get("attributes", {}).get("results")
		print(f"{Fore.LIGHTBLUE_EX}vt url info {Fore.CYAN} {len(vt_url_resultdata)}:{Fore.YELLOW} {vturlinfo.get('data', {}).get('attributes', {}).get('stats')}{Style.RESET_ALL}")
		for vendor in vt_url_resultdata:
			if vt_url_resultdata.get(vendor).get("category") == "malicious":
				print(f"{Fore.CYAN} Vendor: {vendor} result: {vt_url_resultdata.get(vendor).get('result')} method: {vt_url_resultdata.get(vendor).get('method')} {Style.RESET_ALL}")
	
	if "defender_url" in results and results["defender_url"]:
		defenderdata = results["defender_url"]
		print(f"{Fore.LIGHTBLUE_EX}defender data:{Fore.YELLOW} {len(defenderdata.get('Results', []))} {Style.RESET_ALL}")
		if len(defenderdata.get("Results", [])) >= 1:
			results_list = defenderdata.get("Results", [])
			for res in results_list[: args.maxoutput]:
				print(f"{Fore.CYAN} {res.get('Timestamp')} device: {res.get('DeviceName')} action: {res.get('ActionType')} url: {res.get('RemoteUrl')} user: {res.get('InitiatingProcessAccountName')} {res.get('InitiatingProcessAccountUpn')} {Style.RESET_ALL}")
	
	# URLScan.io results
	if "urlscanio" in results and results["urlscanio"]:
		urlscandata = results["urlscanio"]
		if urlscandata and urlscandata.get("total") > 0:
			print(f'{Fore.LIGHTBLUE_EX}urlscanio {Fore.LIGHTBLACK_EX}results:{Fore.RED} {urlscandata.get("total")} ')
			if args.dumpurlscandata:
				for res in urlscandata.get("results")[: args.maxoutput]:
					print(f"{Fore.CYAN} time: {res.get('task').get('time')} vis: {res.get('task').get('visibility')} url: {res.get('task').get('url')} ")
		else:
			logger.warning(f"no urlscanio data for {args.ip}")
	
	# VirusTotal URL results
	if "virustotal_urlinfo_vturl" in results and results["virustotal_urlinfo_vturl"]:
		vturlinfo = results["virustotal_urlinfo_vturl"]
		vt_url_resultdata = vturlinfo.get("data", {}).get("attributes", {}).get("results")
		print(f"{Fore.BLUE}vt url info: {Fore.GREEN}{len(vt_url_resultdata)}: {vturlinfo.get('data', {}).get('attributes', {}).get('stats')}")
		for vendor in vt_url_resultdata:
			if vt_url_resultdata.get(vendor).get("category") == "malicious":
				print(f"{Fore.BLUE}Vendor: {vendor} {Fore.CYAN}result: {vt_url_resultdata.get(vendor).get('result')} method: {vt_url_resultdata.get(vendor).get('method')} ")
	
	# IPWhois results
	if "ipwhois" in results and results["ipwhois"]:
		whois_info = results["ipwhois"]
		print(f"{Fore.LIGHTBLUE_EX}whois\n\t{Fore.CYAN} {whois_info}")
	
	# VirusTotal IP results
	for key in results:
		if key.startswith("virustotal"):
			vtinfo = results[key]
			if vtinfo and not key.endswith("_urlinfo") and not key.endswith("_scanurls"):
				ipaddr = key.replace("virustotal_", "") if "_" in key else args.ip
				last_analysis_stats = vtinfo.get("last_analysis_stats", {})
				last_analysis_results = vtinfo.get("last_analysis_results", {})
				as_owner = vtinfo.get("as_owner", "None")
				total_votes = vtinfo.get("total_votes", {})
				suspicious = last_analysis_stats.get('suspicious')
				malicious = last_analysis_stats.get('malicious')
				malicious += int(total_votes.get("malicious", 0))
				if malicious+suspicious > 0:
					vtforecolor = Fore.RED
				else:
					vtforecolor = Fore.GREEN
				print(f"{Fore.LIGHTBLUE_EX}vt\t{ipaddr} asowner:{Fore.CYAN} {as_owner} vtvotes: {vtforecolor} malicious: {malicious} suspicious: {suspicious}")
				for vendor in last_analysis_results:
					if last_analysis_results.get(vendor).get("category") in ('malware', 'suspicious', "malicious"):
						print(f"{Fore.BLUE}\t{vendor} {Fore.CYAN} result:{Fore.RED}{last_analysis_results.get(vendor).get('result')} {Fore.LIGHTBLUE_EX}{last_analysis_results.get(vendor).get('method')} ")
	
	# AbuseIPDB results
	if "abuseipdb" in results and results["abuseipdb"]:
		abuseipdbdata = results["abuseipdb"]
		score = abuseipdbdata.get("data").get("abuseConfidenceScore")
		score_color = Fore.GREEN
		if score >= 1:
			score_color = Fore.RED
		print(f'{Fore.LIGHTBLUE_EX}abuseipdb Reports:{Fore.CYAN} {abuseipdbdata.get("data").get("totalReports")} abuseConfidenceScore:{score_color} {score} isp: {abuseipdbdata.get("data").get("isp")} country: {abuseipdbdata.get("data").get("countryCode")} hostname:{Fore.CYAN} {abuseipdbdata.get("data").get("hostnames")} domain: {abuseipdbdata.get("data").get("domain")} tor: {abuseipdbdata.get("data").get("isTor")}')
		if args.dumpabusedata:
			for report in abuseipdbdata.get("data").get("reports"):
				print(f'{Fore.CYAN} reportedAt: {report.get("reportedAt")} reporterId: {report.get("reporterId")} comment: {report.get("comment")} ')
	
	# CrowdSec results
	if "crowdsec" in results and results["crowdsec"]:
		data = results["crowdsec"]
		for crowdsecdata in data:
			reputation = crowdsecdata.get("reputation")
			rep_color = Fore.GREEN
			if reputation in ['unknown', 'malicious']:
				rep_color = Fore.RED
			elif reputation == 'suspicious':
				rep_color = Fore.YELLOW
			print(f'{Fore.LIGHTBLUE_EX}crowdsec {crowdsecdata.get("ip")} Reputation:{rep_color} {reputation} confidence: {crowdsecdata.get("confidence")}')
	
	# Graylog results
	for key in results:
		if key.startswith("graylog"):
			glresults = results[key]
			if glresults:
				print_graylog_summary(glresults)
				if not key.startswith("graylog_sslvpnloginfail") and not key.startswith("graylog_ftgd_blk"):
					print_graylog_data(glresults, args)
	
	# Special Graylog queries
	if "sslvpnloginfail" in results and results["sslvpnloginfail"]:
		results_data = results["sslvpnloginfail"]
		if results_data:
			ipaddres_set = set([k.get("message").get("remip") for k in results_data.get("hits").get("hits")])
			print(f"{Fore.LIGHTBLUE_EX}graylog sslvpnloginfail {Fore.CYAN}results: {results_data.get('hits').get('total').get('value')} ipaddres_set: {len(ipaddres_set)}")
			# Additional processing for SSL VPN login failures...
	
	if "ftgd_blk" in results and results["ftgd_blk"]:
		results_data = results["ftgd_blk"]
		if results_data:
			ipaddres_set = set([k.get("message").get("dstip") for k in results_data.get("hits").get("hits")])
			print(f"{Fore.LIGHTBLUE_EX}[2] graylog results:{Fore.YELLOW} {results_data.get('hits').get('total').get('value')} {Fore.LIGHTBLUE_EX}ipaddres_set:{Fore.YELLOW} {len(ipaddres_set)}")
			# Additional processing for FTGD blocks...
	
	# Azure results
	if "azure" in results and results["azure"]:
		azuredata = results["azure"]
		if len(azuredata) >= 1:
			print(f"{Fore.LIGHTBLUE_EX}azure signinlogs:{Fore.GREEN}{len(azuredata)}")
			for logentry in azuredata[: args.maxoutput]:
				timest = logentry.get("TimeGenerated")
				status = json.loads(logentry.get("Status"))
				print(f"{Fore.CYAN}   {timest.ctime()} result: {logentry.get('ResultType')} code: {status.get('errorCode')} {status.get('failureReason')} user: {logentry.get('UserDisplayName')} {logentry.get('UserPrincipalName')} AppDisplayName: {logentry.get('AppDisplayName')} mfa: {logentry.get('MfaDetail')} riskdetail: {logentry.get('RiskDetail')} resourcedisplayname: {logentry.get('ResourceDisplayName')} authenticationrequirement: {logentry.get('AuthenticationRequirement')}")
		else:
			print(f"{Fore.YELLOW}no azure data for {Fore.GREEN}{args.ip}{Style.RESET_ALL}")
	
	# Defender results
	if "defender_indicators" in results and results["defender_indicators"]:
		indicators = results["defender_indicators"]
		if len([k for k in indicators if args.ip in str(k.values())]) >= 1:
			indx = [k for k in indicators if k.get("indicatorValue") == args.ip]
			for ind in indx:
				print(f'{Fore.RED}indicator found: {Fore.GREEN} {ind.get("title")} {ind.get("description")} {Fore.LIGHTBLUE_EX}type: {ind.get("indicatorType")} action: {ind.get("action")} {Fore.LIGHTGREEN_EX} created by: {ind.get("createdBy")}')
		else:
			print(f"{Fore.YELLOW}no indicator found for {Fore.GREEN}{args.ip}{Style.RESET_ALL}")
	
	if "defender_network" in results and results["defender_network"]:
		defenderdata = results["defender_network"]
		if len(defenderdata.get("Results")) >= 1:
			print(f"{Fore.BLUE}defender results:{Fore.GREEN} {len(defenderdata.get('Results'))}")
			results_list = defenderdata.get("Results")
			for res in results_list[: args.maxoutput]:
				print(f"{Fore.LIGHTBLUE_EX}{'':2} {res.get('Timestamp')}\n     {Fore.CYAN}device: {res.get('DeviceName')} user: {res.get('InitiatingProcessAccountName')} remip: {res.get('RemoteIP')}:{res.get('RemotePort')} localip: {res.get('LocalIP')} action: {res.get('ActionType')} \n     remoteurl: {res.get('RemoteUrl')} upn:{res.get('InitiatingProcessAccountUpn')} {Style.RESET_ALL}")
		else:
			print(f"{Fore.YELLOW}no defender results for {Fore.GREEN}{args.ip}{Style.RESET_ALL}")
			

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
