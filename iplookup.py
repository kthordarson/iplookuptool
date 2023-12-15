#!/usr/bin/python
import sys
import os
import argparse
import requests
import socket
import json
from ipaddress import ip_address
from modules.virustotal import get_virustotal_info, get_virustotal_comments, get_virustotal_scanurls, get_virustotal_urlinfo, get_vt_ipinfo
from modules.abuseipdb import get_abuseipdb_data
from modules.ipwhois import get_ipwhois
from modules.spamlookup import spam_lookup
# todo add graylog, azure, defender, ipinfo, hakrevdns, anyrun, urlscan.io, fortiguard, abuse.ch

try:
	from loguru import logger
except ImportError as e:
	logger.error(f'missing loguru package')
	os._exit(-1)

if __name__ == '__main__':
	parsedargs = argparse.ArgumentParser(description="ip address lookup")
	parsedargs.add_argument('--ipaddr', help="ipaddress to lookup", type=str, metavar='ipaddr')
	parsedargs.add_argument('--ipwhois', help="ipwhois lookup", action='store_true', default=True)
	parsedargs.add_argument('--virustotal', help="virustotal lookup", action='store_true', default=False)
	parsedargs.add_argument('--vturl', help="virustotal url lookup", type=str )
	parsedargs.add_argument('--spam', help="spam lookup", action='store_true', default=False)
	parsedargs.add_argument('--abuseipdb', help="abuseipdb lookup", action='store_true', default=False)
	parsedargs.add_argument('--all', help="use all lookups", action='store_true', default=False)
	args = parsedargs.parse_args()
	vtinfo = None
	abuseipdbdata = None
	try:
		ipaddress = ip_address(args.ipaddr).exploded
	except ValueError as e:
		logger.warning(f'[!] {e} {type(e)} for address {args.ipaddr}')
		ipaddress = None
	if args.vturl:
		infourl = get_virustotal_scanurls(args.vturl)
		print(f'getting info from vt url: {infourl}')
		vturlinfo = get_virustotal_urlinfo(infourl)
		resultdata = vturlinfo.get('data').get('attributes').get('results')
		print(f"vt url info {len(resultdata)}: {vturlinfo.get('data').get('attributes').get('stats')}")
		for vendor in resultdata:
			if resultdata.get(vendor).get('category') == 'malicious':
				print(f'Vendor: {vendor} result: {resultdata.get(vendor).get('result')} method: {resultdata.get(vendor).get('method')} ')
	if args.all:
		args.virustotal = True
		args.abuseipdb = True
		args.spam = True
	if args.ipwhois and ipaddress:
		whois_info = get_ipwhois(args.ipaddr)
		print(f'whois: {whois_info}')
	if args.virustotal and ipaddress:
		vtinfo = get_vt_ipinfo(args.ipaddr)
		if vtinfo:
			vt_las = vtinfo.last_analysis_stats
			vt_res = vtinfo.last_analysis_results
			print(f'vt asowner: {vtinfo.as_owner} vtvotes: {vtinfo.total_votes}')
			print(f'vt last_analysis_stats: {vt_las}')
			for vendor in vt_res:
				if vt_res.get(vendor).get('category') == 'malicious':
					print(f'Vendor: {vendor} result: {vt_res.get(vendor).get('result')} method: {vt_res.get(vendor).get('method')} ')
	if args.abuseipdb and ipaddress:
		abuseipdbdata = get_abuseipdb_data(args.ipaddr)
		if abuseipdbdata:
			print(f'abuseipdb Reports: {abuseipdbdata.get("data").get("totalReports")} abuseConfidenceScore: {abuseipdbdata.get("data").get("abuseConfidenceScore")} isp: {abuseipdbdata.get("data").get("isp")} country: {abuseipdbdata.get("data").get("countryCode")}')
			print(f'abuseipdb hostname: {abuseipdbdata.get("data").get("hostnames")} domain: {abuseipdbdata.get("data").get("domain")} tor: {abuseipdbdata.get("data").get("isTor")}')
