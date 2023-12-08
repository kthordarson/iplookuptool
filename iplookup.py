#!/usr/bin/python
import sys
import os
import argparse
import requests
import socket
import json

try:
	from ipwhois import IPWhois
	from ipwhois.exceptions import HostLookupError, HTTPLookupError
except ImportError as e:
	logger.error(f'missing ipwhois package')
	os._exit(-1)

try:
	from loguru import logger
except ImportError as e:
	logger.error(f'missing loguru package')
	os._exit(-1)

try:
	from vt import Client
except ImportError as e:
	logger.error(f'missing virustotal package')
	os._exit(-1)

VTAPIKEY = os.environ.get("VTAPIKEY")
ABUSEIPDBAPIKEY = os.environ.get("ABUSEIPDBAPIKEY")
# todo add ipinfo, hakrevdns

def get_abuseipdb_data(ipaddr, maxdays=30):
	# https://www.abuseipdb.com/api.html
	# https://www.abuseipdb.com/check/[IP]/json?key=[API_KEY]&days=[DAYS]
	headers = {'Key': ABUSEIPDBAPIKEY, 'Accept' : 'application/json'	}
	params = { 'maxAgeInDays' : maxdays, 'ipAddress' : ipaddr, 'verbose' :'True',	}
	response = None
	jsonresp = None
	try:
		response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
		# response = requests.get(f'https://www.abuseipdb.com/check/{ipaddr}/json?key={ABUSEIPDBAPIKEY}&days={maxdays}&verbose', headers=headers, params=params)
	except Exception as e:
		logger.error(f'[!] {e} {type(e)}')
		return None
	try:
		jsonresp = response.json()
	except Exception as e:
		logger.error(f'[!] {e} {type(e)} while parsing json response')
		return None
	if response and jsonresp:
		data = jsonresp
		data['url'] = f'https://www.abuseipdb.com/check/{ipaddr}/json?key={ABUSEIPDBAPIKEY}&days={maxdays}&verbose'
		return data
	else:
		logger.error(f'Unknown error for {ipaddr} response: {response} json: {jsonresp}')
		return None

def get_abuseipdb_info(data):
	# parse data from get_abuseipdb_data
	return None

def get_ipwhois(ipaddr):
	result = None
	try:
		obj = IPWhois(ipaddr)
		rdap = obj.lookup_rdap()
		result = f"{rdap['asn_description']};{rdap['network']['name']};{rdap['network']['cidr']};{rdap['network']['start_address']};{rdap['network']['end_address']}"
		return result
	except HTTPLookupError as e:
		logger.warning(f'[!] Error: {e} for address {ipaddr}')
	except ValueError as e:
		logger.warning(f'[!] {e} invalid address {ipaddr}')
	except Exception as e:
		logger.error(f'[!] Error: {e} {type(e)} for address {ipaddr}')
	finally:
		return result

def get_virustotal_info(ipaddr):
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}"
	headers = {
    	"accept": "application/json",
    	"x-apikey": VTAPIKEY
		}
	try:
		response = requests.get(url, headers=headers)
	except Exception as e:
		logger.error(f'[!] {e} {type(e)} addr: {ipaddr}')
		return None
	#  [resptext['data']['attributes']['last_analysis_results'][k] for k in resptext['data']['attributes']['last_analysis_results']]
	# results = response.text['data']['attributes']['last_analysis_stats']
	jsonresults = response.json()
	# results['data']['attributes']['last_analysis_stats']
	return jsonresults['data']['attributes'] # ['last_analysis_stats']

def get_vt_ipinfo(ipaddr):
	try:
		client = Client(VTAPIKEY)
	except Exception as e:
		logger.error(f'[!] {e} {type(e)} addr: {ipaddr}')
		return None
	try:	
		vtipinfo = client.get_object(f'/ip_addresses/{ipaddr}')
	except Exception as e:
		logger.error(f'[!] {e} {type(e)} addr: {ipaddr}')
		return None
	client.close()
	return vtipinfo

def spam_lookup(ipaddr):
	bl = ['ubl.unsubscore.com','dyna.spamrats.com','dnsbl-3.uceprotect.net','dnsbl-1.uceprotect.net','rf.senderbase.org','spam.dnsbl.sorbs.net','bl.spameatingmonkey.net','bl.spamcannibal.org','socks.dnsbl.sorbs.net','spam.spamrats.com','smtp.dnsbl.sorbs.net','ips.backscatterer.org','bl.blocklist.de','zen.spamhaus.org','rbl.interserver.net','rbl.abuse.ro','dnsbl-2.uceprotect.net','cncdl.anti-spam.org','dnsbl.dronebl.org','query.senderbase.org','sa.senderbase.org','cbl.anti-spam.org','b.barracudacentral.org','spam.dnsbl.anonmails.de','web.dnsbl.sorbs.net','pbl.spamhaus.org','bl.spamcop.net','http.dnsbl.sorbs.net','dnsbl-0.uceprotect.net','dnsbl.sorbs.net','csi.cloudmark.com','zombie.dnsbl.sorbs.net','noptr.spamrats.com','xbl.spamhaus.org','bl.score.senderscore.com','bl.mailspike.net','sbl.spamhaus.org','misc.dnsbl.sorbs.net','dul.dnsbl.sorbs.net','cbl.abuseat.org','multi.surbl.org']
	ip_rev = '.'.join(str(ipaddr).split('.')[::-1])
	listed = 0
	l_rbl  = []
	for i in bl:
		try:
			#Lookup  happens here - if gethostbyname fails the ip is not listed
			# logger.debug(f'[l] i: {i} {ip_rev}')
			socket.gethostbyname(ip_rev + '.' + i + '.')  # final dot to avoid localhost lookups in some env
			l_rbl += [i]
			listed+= 1
		except socket.gaierror as e:
			logger.error(f'[!] Error: {e} {type(e)} for address {ipaddr}')
			x = 0
			return None
		except Exception as e:
			logger.error(f'[!] Error: {e} {type(e)} for address {ipaddr}')
			x = 0
			return None
	return [str(listed), l_rbl]	

if __name__ == '__main__':
	if not VTAPIKEY:
		logger.error(f'missing virus total api key')
		os._exit(-1)
	if not ABUSEIPDBAPIKEY:
		logger.error(f'missing abuseipdb api key')
		os._exit(-1)
	parsedargs = argparse.ArgumentParser(description="ip address lookup")
	parsedargs.add_argument('--ipaddr', help="ipaddress to lookup", type=str, metavar='ipaddr', required=True)
	parsedargs.add_argument('--ipwhois', help="ipwhois lookup", action='store_true', default=True)
	parsedargs.add_argument('--virustotal', help="virustotal lookup", action='store_true', default=False)
	parsedargs.add_argument('--spam', help="spam lookup", action='store_true', default=False)
	parsedargs.add_argument('--abuseipdb', help="abuseipdb lookup", action='store_true', default=False)
	parsedargs.add_argument('--all', help="use all lookups", action='store_true', default=False)
	args = parsedargs.parse_args()
	if args.all:
		args.virustotal = True
		args.abuseipdb = True
		args.spam = True
	if args.ipwhois:
		whois_info = get_ipwhois(args.ipaddr)
		print(f'whois: {whois_info}')
	if args.virustotal:
		vtinfo = get_vt_ipinfo(args.ipaddr)
		vt_las = vtinfo.last_analysis_stats
		vt_res = vtinfo.last_analysis_results
		print(f'vt asowner: {vtinfo.as_owner} vtvotes: {vtinfo.total_votes}')
		print(f'vt last_analysis_stats: {vt_las}')
		for vendor in vt_res:
			if vt_res.get(vendor).get('category') == 'malicious':
				print(f'Vendor: {vendor} result: {vt_res.get(vendor).get('result')} method: {vt_res.get(vendor).get('method')} ')
	if args.abuseipdb:
		abuseipdbdata = get_abuseipdb_data(args.ipaddr)
		print(f'abuseipdb Reports: {abuseipdbdata.get("data").get("totalReports")} abuseConfidenceScore: {abuseipdbdata.get("data").get("abuseConfidenceScore")} isp: {abuseipdbdata.get("data").get("isp")} country: {abuseipdbdata.get("data").get("countryCode")}')
		print(f'abuseipdb hostname: {abuseipdbdata.get("data").get("hostnames")} domain: {abuseipdbdata.get("data").get("domain")} tor: {abuseipdbdata.get("data").get("isTor")}')
