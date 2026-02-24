import os
import pandas as pd
import re
from datetime import datetime
from collections import Counter
from opensearchpy import AsyncOpenSearch
from loguru import logger
from colorama import Fore, Style
import urllib3
urllib3.disable_warnings()

GRAYLOGAPIKEY = os.environ.get('GRAYLOGAPIKEY')
IPFIELDS = [
	'srcip',
	'dstip',
	'remip',
	'IpAddress',
	'transip',
	'src',
	'dst',
	'ClientIP',
	'VserverServiceIP',
	'VserverAddress',
	'NatIPaddress',
	'Source',
	'SourceAddress',
	'DestinationAddress',
	'VserverAddress',
	'ipAddress',
	'client_ipaddress',
	'InitiatedByUserIpAddress'
]

def format_datetime(input_str):
	"""
	Convert input datetime string or Unix timestamp to formatted string (YYYY-MM-DD HH:MM:SS).

	Args:
		input_str (str): Input string in format 'YYYY-MM-DD HH:MM:SS.sss' or Unix timestamp

	Returns:
		str: Formatted datetime string or error message
	"""
	try:
		# Check if input is a Unix timestamp (all digits)
		if input_str.isdigit():
			# Convert Unix timestamp (milliseconds) to datetime
			dt = datetime.fromtimestamp(int(input_str) / 1000)
			return dt.strftime("%Y-%m-%d %H:%M:%S")

		# Check if input matches datetime format
		pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?'
		if re.match(pattern, input_str):
			# Parse datetime string
			dt = datetime.strptime(input_str.split('.')[0], "%Y-%m-%d %H:%M:%S")
			return dt.strftime("%Y-%m-%d %H:%M:%S")

		return "Invalid input format"
	except (ValueError, TypeError):
		return "Invalid input format"

async def graylog_search_ip(args, range=86400):
	query = {'query': {'multi_match': {'query': args.ip,'fields': IPFIELDS}}}
	res = None
	if not os.environ.get('OPENSEARCHOST'):
		logger.error('OPENSEARCHOST environment variable not set')
		return res
	if not os.environ.get('OPENSEARCHAUTHPASS'):
		logger.error('OPENSEARCHAUTHPASS environment variable not set')
		return res
	async with AsyncOpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False, ssl_show_warn=False) as client:
		# q='RemoteMGNT'
		# range=(86400)
		try:
			res = await client.search(body=query, size=5000)
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			raise e
		await client.close()
		return res

async def graylog_search(query, range=86400):
	query = {'query': {'multi_match': {'query': query,'fields': IPFIELDS}}}
	res = {}
	if not os.environ.get('OPENSEARCHOST'):
		logger.error('OPENSEARCHOST environment variable not set')
		return res
	if not os.environ.get('OPENSEARCHAUTHPASS'):
		logger.error('OPENSEARCHAUTHPASS environment variable not set')
		return res
	async with AsyncOpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False, ssl_show_warn=False) as client:
		# q='RemoteMGNT'
		# range=(86400)
		try:
			res = await client.search(body=query, size=10000)
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)} for query={query}')
			raise e
		# logger.debug(f'[s] searchres: {res} q={query} range={range}')
		return res

async def graylog_freetext_search(search_text, range=86400):
	"""
	Perform a free text search across all fields in the OpenSearch index
	"""
	# query = {"query": {"simple_query_string": {"query": search_text,"default_operator": "AND"}}}
	query = {"query": {"query_string": {"query": search_text,"default_operator": "AND"}}}

	# searches all fields
	# query = {"query": {"match": {"_all": search_text}}}
	if not os.environ.get('OPENSEARCHOST'):
		logger.error('OPENSEARCHOST environment variable not set')
		return {}
	if not os.environ.get('OPENSEARCHAUTHPASS'):
		logger.error('OPENSEARCHAUTHPASS environment variable not set')
		return {}

	async with AsyncOpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False, ssl_show_warn=False) as client:
		try:
			res = await client.search(body=query, size=10000)
		except Exception as e:
			logger.error(f'graylog freetext search error: {e} {type(e)}')
			raise e
		return res

def summarize_graylog_results(search_results):
	"""
	Summarize results from graylog_freetext_search
	"""
	if not search_results or not search_results.get('hits', {}).get('hits'):
		return {
			'total_results': 0,
			'results_analyzed': 0,
			'summary': 'No results found',
			'log_types': {},
			'event_types': {},
			'top_actions': {},
			'top_source_ips': {},
			'top_dest_ips': {},
			'top_devices': {},
			'top_services': {},
			'top_countries': {},
			'top_modules': {},
			'top_vservers': {},
			'top_destinations': {},
			'top_source_addresses': {},
			'traffic_stats': {
				'total_bytes_received': 0,
				'total_bytes_sent': 0,
				'unique_source_count': 0,
				'unique_destination_count': 0
			},
			'time_range': {
				'earliest': None,
				'latest': None,
				'count': 0
			}
		}
	try:
		hits = search_results.get('hits', {}).get('hits', [])
	except TypeError as e:
		logger.error(f'Error extracting hits from search results: {e}')
		return {
			'total_results': 0,
			'results_analyzed': 0,
			'summary': 'Invalid search results format',
			'log_types': {},
			'event_types': {},
			'top_actions': {},
			'top_source_ips': {},
			'top_dest_ips': {},
			'top_devices': {},
			'top_services': {},
			'top_countries': {},
			'top_modules': {},
			'top_vservers': {},
			'top_destinations': {},
			'top_source_addresses': {},
			'traffic_stats': {
				'total_bytes_received': 0,
				'total_bytes_sent': 0,
				'unique_source_count': 0,
				'unique_destination_count': 0
			},
			'time_range': {
				'earliest': None,
				'latest': None,
				'count': 0
			}
		}
	try:
		total_results = search_results.get('hits', {}).get('total', {}).get('value', 0)
	except KeyError as e:
		logger.error(f'Error extracting total results: {e}')
		return {
			'total_results': 0,
			'results_analyzed': 0,
			'summary': 'Invalid search results format',
			'log_types': {},
			'event_types': {},
			'top_actions': {},
			'top_source_ips': {},
			'top_dest_ips': {},
			'top_devices': {},
			'top_services': {},
			'top_countries': {},
			'top_modules': {},
			'top_vservers': {},
			'top_destinations': {},
			'top_source_addresses': {},
			'traffic_stats': {
				'total_bytes_received': 0,
				'total_bytes_sent': 0,
				'unique_source_count': 0,
				'unique_destination_count': 0
			},
			'time_range': {
				'earliest': None,
				'latest': None,
				'count': 0
			}
		}

	# Extract all _source data
	sources = [hit.get('_source', {}) for hit in hits]

	# Analyze data types/categories
	log_types = Counter()
	event_types = Counter()
	actions = Counter()
	source_ips = Counter()
	dest_ips = Counter()
	devices = Counter()
	services = Counter()
	countries = Counter()
	modules = Counter()
	vservers = Counter()
	destinations = Counter()
	source_addresses = Counter()

	# For Citrix NetScaler data
	total_bytes_recv = 0
	total_bytes_sent = 0
	unique_sources = set()
	unique_destinations = set()

	# Common field mappings for different log types
	for source in sources:
		# Log types
		if 'type' in source:
			log_types[source['type']] += 1

		# Event types
		if 'eventtype' in source:
			event_types[source['eventtype']] += 1

		# Actions
		if 'action' in source:
			actions[source['action']] += 1

		# Source IPs
		for ip_field in IPFIELDS:  # ['srcip', 'Remote_ip', 'ClientIP', 'source','SourceAddress','VserverAddress','NatIPaddress', 'transip', 'client_ipaddress']:
			if ip_field in source and source[ip_field]:
				try:
					# Only process if it's a string (IP address)
					if isinstance(source[ip_field], str):
						source_ips[source[ip_field]] += 1
					break
				except (TypeError, KeyError):
					logger.debug(f'Skipping non-string source IP field {ip_field}: {type(source[ip_field])}')
					continue

		# Destination IPs
		for ip_field in IPFIELDS:  # ['dstip', 'VserverServiceIP']:
			if ip_field in source and source[ip_field]:
				if isinstance(source[ip_field], str):
					dest_ips[source[ip_field]] += 1
				break

		# Devices
		for device_field in ['devname', 'hostname', 'DeviceName']:
			if device_field in source and source[device_field]:
				devices[source[device_field]] += 1
				break

		# Services
		if 'service' in source:
			services[source['service']] += 1

		# Countries
		for country_field in ['srccountry', 'dstcountry']:
			if country_field in source and source[country_field]:
				countries[source[country_field]] += 1

		# Additional analysis for Citrix NetScaler data
		if 'module' in source:
			modules[source['module']] += 1

		if 'Vserver' in source:
			vservers[source['Vserver']] += 1

		if 'Destination' in source:
			destinations[source['Destination']] += 1

		if 'SourceAddress' in source:
			source_addresses[source['SourceAddress']] += 1
			unique_sources.add(source['SourceAddress'])

		if 'DestinationAddress' in source:
			unique_destinations.add(source['DestinationAddress'])

		# Traffic analysis
		if 'Total_bytes_recv' in source:
			try:
				total_bytes_recv += int(source['Total_bytes_recv'])
			except (ValueError, TypeError):
				pass

		if 'Total_bytes_send' in source:
			try:
				total_bytes_sent += int(source['Total_bytes_send'])
			except (ValueError, TypeError):
				pass

	# Time range analysis
	timestamps = []
	for source in sources:
		for ts_field in ['timestamp', 'gl2_receive_timestamp', 'eventtime']:
			if ts_field in source and source[ts_field]:
				# Convert all timestamps to strings for consistent comparison
				# if len(str(source[ts_field])) == 13:
				# If timestamp is in milliseconds, convert to seconds
				# 	ts_temp = datetime.fromtimestamp(int(source[ts_field] // 1000), timezone.utc)
				ts_value = str(source[ts_field])
				ts_value_string = format_datetime(ts_value)
				timestamps.append(ts_value_string)
				break

	# Build summary
	summary = {
		'total_results': total_results,
		'results_analyzed': len(hits),
		'log_types': dict(log_types.most_common(10)),
		'event_types': dict(event_types.most_common(10)),
		'top_actions': dict(actions.most_common(10)),
		'top_source_ips': dict(source_ips.most_common(10)),
		'top_dest_ips': dict(dest_ips.most_common(10)),
		'top_devices': dict(devices.most_common(10)),
		'top_services': dict(services.most_common(10)),
		'top_countries': dict(countries.most_common(10)),
		'top_modules': dict(modules.most_common(10)),
		'top_vservers': dict(vservers.most_common(10)),
		'top_destinations': dict(destinations.most_common(10)),
		'top_source_addresses': dict(source_addresses.most_common(10)),
		'traffic_stats': {
			'total_bytes_received': total_bytes_recv,
			'total_bytes_sent': total_bytes_sent,
			'unique_source_count': len(unique_sources),
			'unique_destination_count': len(unique_destinations)
		},
		'time_range': {
			'earliest': min(timestamps) if timestamps else None,
			'latest': max(timestamps) if timestamps else None,
			'count': len(timestamps)
		}
	}

	return summary

def print_graylog_summary(search_results):
	"""
	Print a formatted summary of graylog search results
	"""
	summary = summarize_graylog_results(search_results)
	try:
		print(f"{Fore.CYAN}Graylog Total Results: {Fore.YELLOW}{summary['total_results']} {Fore.CYAN}Analyzed: {Fore.YELLOW}{summary['results_analyzed']}")
	except KeyError as e:
		logger.error(f'Error printing graylog summary: {e} summary={summary}')
		print(f"{Fore.RED}Error: Invalid search results format{Style.RESET_ALL}")
		return

	if summary['log_types']:
		print(f"{Fore.LIGHTBLUE_EX}Log Types:", end='')
		for log_type, count in summary['log_types'].items():
			print(f"  {Fore.CYAN}{log_type}: {Fore.YELLOW}{count}", end='')
		print()
	if summary['event_types']:
		print(f"{Fore.LIGHTBLUE_EX}Event Types:", end='')
		for event_type, count in summary['event_types'].items():
			print(f"  {Fore.CYAN}{event_type}: {Fore.YELLOW}{count}", end='')
		print()
	if summary['top_actions']:
		print(f"{Fore.LIGHTBLUE_EX}Top Actions:", end='')
		for action, count in summary['top_actions'].items():
			print(f"  {Fore.CYAN}{action}: {Fore.YELLOW}{count}", end='')
		print()
	if summary['top_source_ips']:
		print(f"{Fore.LIGHTBLUE_EX}Top Source IPs:")
		for ip, count in summary['top_source_ips'].items():
			print(f"  {Fore.CYAN}{ip}: {Fore.YELLOW}{count}")

	if summary['top_dest_ips']:
		print(f"{Fore.LIGHTBLUE_EX}Top Destination IPs:")
		for ip, count in summary['top_dest_ips'].items():
			print(f"  {Fore.CYAN}{ip}: {Fore.YELLOW}{count}")

	if summary['top_devices']:
		print(f"{Fore.LIGHTBLUE_EX}Top Devices:")
		for device, count in summary['top_devices'].items():
			print(f"  {Fore.CYAN}{device}: {Fore.YELLOW}{count}")

	if summary['top_services']:
		print(f"{Fore.LIGHTBLUE_EX}Top Services:")
		for service, count in summary['top_services'].items():
			print(f"  {Fore.CYAN}{service}: {Fore.YELLOW}{count}")

	if summary['top_countries']:
		print(f"{Fore.LIGHTBLUE_EX}Top Countries:")
		for country, count in summary['top_countries'].items():
			print(f"  {Fore.CYAN}{country}: {Fore.YELLOW}{count}")

	if summary['top_modules']:
		print(f"{Fore.LIGHTBLUE_EX}Top Modules:")
		for module, count in summary['top_modules'].items():
			print(f"  {Fore.CYAN}{module}: {Fore.YELLOW}{count}", end='')
		print()
	if summary['top_vservers']:
		print(f"{Fore.LIGHTBLUE_EX}Top Virtual Servers:")
		for vserver, count in summary['top_vservers'].items():
			print(f"  {Fore.CYAN}{vserver}: {Fore.YELLOW}{count}")

	if summary['top_destinations']:
		print(f"{Fore.LIGHTBLUE_EX}Top Destinations:")
		for dest, count in summary['top_destinations'].items():
			print(f"  {Fore.CYAN}{dest}: {Fore.YELLOW}{count}")

	if summary['traffic_stats']['total_bytes_received'] > 0 or summary['traffic_stats']['total_bytes_sent'] > 0:
		print(f"{Fore.LIGHTBLUE_EX}Traffic Statistics:")
		print(f"  {Fore.CYAN}Total Bytes Received: {Fore.YELLOW}{summary['traffic_stats']['total_bytes_received']:,}")
		print(f"  {Fore.CYAN}Total Bytes Sent: {Fore.YELLOW}{summary['traffic_stats']['total_bytes_sent']:,}")
		print(f"  {Fore.CYAN}Unique Sources: {Fore.YELLOW}{summary['traffic_stats']['unique_source_count']}")
		print(f"  {Fore.CYAN}Unique Destinations: {Fore.YELLOW}{summary['traffic_stats']['unique_destination_count']}")

	if summary['time_range']['earliest'] and summary['time_range']['latest']:
		print(f"{Fore.LIGHTBLUE_EX}Time Range:", end='')
		print(f"  {Fore.CYAN}Earliest: {Fore.YELLOW}{summary['time_range']['earliest']}", end='')
		print(f"  {Fore.CYAN}Latest: {Fore.YELLOW}{summary['time_range']['latest']}", end='')
		print(f"  {Fore.CYAN}Total Events with Timestamps: {Fore.YELLOW}{summary['time_range']['count']}", end='')
		print()

	print(f"{Style.RESET_ALL}")

def print_graylog_data(results, args):
	df = pd.DataFrame([k["_source"] for k in results.get("hits").get("hits")])
	# Additional detailed analysis
	# if results.get("hits").get("total").get("value") > 0:
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
		# for res in results.get("hits").get("hits")[: args.maxoutput]:
		index_list = list(set([k.get('_index') for k in results.get("hits").get("hits")]))
		# index_temp_name_list = list(set([k.split('_')[0] for k in index_list]))
		# index_temp_idx_list = list(set([k.split('_')[1] for k in index_list]))
		# indextmp = [{'idxname':k.split('_')[0],'idxnum':k.split('_')[1]} for k in index_list]
		for index_name in index_list:
			index_hits = [k for k in results.get("hits").get("hits") if k['_index'] == index_name]
			print(f"{Fore.LIGHTGREEN_EX}{index_name} hits: {Fore.CYAN}{len(index_hits)} {Fore.RESET} ")
			# for idx,res in enumerate(results.get("hits").get("hits")):
			for idx,res in enumerate(index_hits):
				res_idx = res.get("_index")
				res_msg = res.get("_source")
				if idx >= args.maxoutput:
					if args.debug:
						logger.info(f"graylog max {idx} output {args.maxoutput} reached for index {index_name}")
						# logger.debug(f'res_msgkeys: {res_msg.keys()} ')
					break
				if res_idx != index_name:
					if args.debug:
						logger.warning(f"{res_idx} != {index_name}  - skipping")
					break
				elif res_idx == index_name:
					blacklisted = res_msg.get('blacklisted', False)
					blkcolor = Fore.RED if blacklisted else Fore.GREEN
					if 'fgutm' in res_idx:
						print(f"\t{Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} type:{res_msg.get('type')} subtype:{res_msg.get('subtype')} {Fore.CYAN} action:{res_msg.get('action')} {blkcolor}blacklisted: {blacklisted} blksource: {res_msg.get('blksource')} srcip:{res_msg.get('srcip')} dstip:{res_msg.get('dstip')} tranip:{res_msg.get('tranip')} service: {res_msg.get('service')} url:{res_msg.get('url')} ")
					if 'fortitraffic' in res_idx:
						print(f"\t{Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} type:{res_msg.get('type')} subtype:{res_msg.get('subtype')} {Fore.CYAN} action:{res_msg.get('action')} {blkcolor}blacklisted: {blacklisted} blksource: {res_msg.get('blksource')} srcip:{res_msg.get('srcip')} dstip:{res_msg.get('dstip')} dstport:{res_msg.get('dstport')}  tranip:{res_msg.get('tranip')} service: {res_msg.get('service')} url:{res_msg.get('url')} ")
					elif 'fgvpn' in res_idx:
						print(f"\t{Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} type:{res_msg.get('type')} {Fore.CYAN} action:{res_msg.get('action')} remip:{res_msg.get('remip')}  msg: {res_msg.get('msg')} {blkcolor}blacklisted: {blacklisted} blksource: {res_msg.get('blksource')} ")
					elif 'cerberusftp' in res_idx:
						print(f"\t{Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} ftp_action:{res_msg.get('ftp_action')} ftp_user:{res_msg.get('ftp_user')} {Fore.CYAN} client_ipaddress:{res_msg.get('client_ipaddress')}")
					elif "azsignin" in res_idx:
						# print(f'res: {res_msg.keys()}')
						print(f"\t{Fore.BLUE}ts:{res_msg.get('gl2_receive_timestamp')} res:{Fore.LIGHTBLUE_EX}{res_msg.get('ResultDescription')} app:{Fore.LIGHTGREEN_EX}{res_msg.get('AppdisplayName')} ip:{Fore.LIGHTBLUE_EX}{res_msg.get('IpAddress')} id:{Fore.LIGHTCYAN_EX}{res_msg.get('Identity')} resource:{Fore.GREEN}{res_msg.get('ResourceDisplayName')} blacklisted: {Fore.LIGHTBLUE_EX}{res_msg.get('blacklisted')} Location: {res_msg.get('Location')}")
					elif 'azaudit' in res_idx:
						print(f"\t{Fore.BLUE}ts:{res_msg.get('gl2_receive_timestamp')} ActivityDisplayName:{Fore.LIGHTBLUE_EX}{res_msg.get('ActivityDisplayName')} app:{Fore.LIGHTGREEN_EX}{res_msg.get('AppdisplayName')} ip:{Fore.LIGHTBLUE_EX}{res_msg.get('IpAddress')} id:{Fore.LIGHTCYAN_EX}{res_msg.get('Identity')} resource:{Fore.GREEN}{res_msg.get('ResourceDisplayName')} blacklisted: {Fore.LIGHTBLUE_EX}{res_msg.get('blacklisted')} Location: {res_msg.get('Location')} ResultSignature: {res_msg.get('ResultSignature')}")
					elif "msgraph" in res_idx:
						print(f"\t{Fore.CYAN}{res_msg.get('gl2_receive_timestamp')} {Fore.BLUE}method: {Fore.LIGHTBLUE_EX}{res_msg.get('RequestMethod')} dispname:{res_msg.get('displayName')} ip:{res_msg.get('IpAddress')} dstip:{res_msg.get('dstip')} {res_msg.get('RequestUri')}")
					elif "securityaudit" in res_idx:
						print(f"\t{Fore.CYAN}{res_msg.get('gl2_receive_timestamp')} user:{Fore.LIGHTBLUE_EX}{res_msg.get('username')} computer:{Fore.LIGHTGREEN_EX}{res_msg.get('computer_name')} {Fore.BLUE}event_id: {Fore.LIGHTBLUE_EX}{res_msg.get('event_id')} {res_msg.get('event_outcome')} {res_msg.get('IpAddress')} {res_msg.get('event_status_text')} task:{res_msg.get('task')}")
					elif 'citrixdefault' in res_idx:
						if res_msg.get('blacklisted') and res_msg.get("blksource") != 'samskipexternal' and res_msg.get("blksource") != 'citrix_tcp_srcblacklisted':
							blk_text = f'{Fore.RED} blacklisted {res_msg.get("blacklisted")} {res_msg.get("blksource")}'
						elif res_msg.get('blacklisted') and res_msg.get("blksource") == 'samskipexternal' or res_msg.get("blksource") != 'citrix_tcp_srcblacklisted':
							blk_text = f'{Fore.GREEN} blacklisted {res_msg.get("blacklisted")} {res_msg.get("blksource")}'
						else:
							blk_text = f'{Fore.YELLOW} blacklisted {res_msg.get("blacklisted")} '
						print(f"\t{Fore.YELLOW}{Fore.BLUE}ts:{res_msg.get('timestamp')} {blk_text} {Fore.BLUE} type: {res_msg.get('type')} module:{res_msg.get('module')} ClientIP:{res_msg.get('ClientIP')} SourceAddress:{res_msg.get('SourceAddress')} method:{res_msg.get('method')} {Fore.CYAN} nsmodule:{res_msg.get('nsmodule')} src:{res_msg.get('src')} url:{res_msg.get('url')} dst: {res_msg.get('dst')} hostname: {res_msg.get('hostname')} ")
					else:
						print(f"\t{Fore.YELLOW}{Fore.BLUE}ts:{res_msg.get('timestamp')} {Fore.GREEN} type:{res_msg.get('type')} subtype:{res_msg.get('subtype')} {Fore.CYAN} action:{res_msg.get('action')} srcip:{res_msg.get('srcip')} dstip:{res_msg.get('dstip')} tranip:{res_msg.get('tranip')} service: {res_msg.get('service')} url:{res_msg.get('url')} srcname:{res_msg.get('srcname')}")
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

if __name__ == '__main__':
	pass
