import os
import re
from datetime import datetime, timezone
from collections import Counter
from opensearchpy import AsyncOpenSearch
from loguru import logger
from colorama import Fore, Style
import urllib3
urllib3.disable_warnings()
GRAYLOGAPIKEY = os.environ.get('GRAYLOGAPIKEY')

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
	
async def graylog_search_ip(ip_address, range=86400):
	# search = SearchuniversalrelativeApi()
	# client = OpenSearch(hosts=os.environ.get('GRAYLOG_HOST'), use_ssl=False, verify_certs=False, http_auth=(os.environ.get('GRAYLOG_USER'),os.environ.get('GRAYLOG_PASS')))
	# ipaddr = args.host  # '31.209.157.27'
	# query = {'size': 50,'query': {'multi_match': {'query': ip_address,'fields': ['srcip', 'dstip', 'remip', 'IpAddress']}}}
	query = {'query': {'multi_match': {'query': ip_address,'fields': ['srcip', 'dstip', 'remip', 'IpAddress', 'src', 'dst', 'ClientIP','VserverServiceIP','NatIPaddress','Source', 'SourceAddress','VserverAddress']}}}
	res = None
	async with AsyncOpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False, ssl_show_warn=False) as client:
		# q='RemoteMGNT'
		# range=(86400)
		try:
			res = await client.search(body=query, size=5000)
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
			raise e
		# logger.debug(f'[s] searchres: {res} q={query} range={range}')
		finally:
			await client.close()
			return res

async def graylog_search(query, range=86400):
	# search = SearchuniversalrelativeApi()
	# client = OpenSearch(hosts=os.environ.get('GRAYLOG_HOST'), use_ssl=False, verify_certs=False, http_auth=(os.environ.get('GRAYLOG_USER'),os.environ.get('GRAYLOG_PASS')))
	# ipaddr = args.host  # '31.209.157.27'
	# query = {'size': 5,'query': {'multi': {'query': query}}}  # ,'fields': ['srcip', 'dstip']}}}
	# urlquery = {'query': {'multi_match': {'query': url,'fields': ['url', 'request_path']}}}
	query = {'query': {'multi_match': {'query': query,'fields': ['url', 'request_path']}}}
	async with AsyncOpenSearch([os.environ.get('OPENSEARCHOST')], http_auth=(os.environ.get('OPENSEARCHAUTHPASS'), os.environ.get('OPENSEARCHAUTHPASS')), use_ssl=True, verify_certs=False, ssl_show_warn=False) as client:
		# q='RemoteMGNT'
		# range=(86400)
		try:
			res = await client.search(body=query, size=10000)
		except Exception as e:
			logger.error(f'graylog search error: {e} {type(e)}')
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
		for ip_field in ['srcip', 'Remote_ip', 'ClientIP', 'source','SourceAddress','VserverAddress','NatIPaddress']:
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
		for ip_field in ['dstip', 'VserverServiceIP']:
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
		print(f"\n{Fore.LIGHTBLUE_EX}=== Graylog Search Results Summary ==={Style.RESET_ALL}")
		print(f"{Fore.CYAN}Total Results: {Fore.YELLOW}{summary['total_results']}")
		print(f"{Fore.CYAN}Analyzed: {Fore.YELLOW}{summary['results_analyzed']}")
	except KeyError as e:
		logger.error(f'Error printing graylog summary: {e} summary={summary}')
		print(f"{Fore.RED}Error: Invalid search results format{Style.RESET_ALL}")
		return
	
	if summary['log_types']:
		print(f"\n{Fore.LIGHTBLUE_EX}Log Types:")
		for log_type, count in summary['log_types'].items():
			print(f"  {Fore.CYAN}{log_type}: {Fore.YELLOW}{count}")
	
	if summary['event_types']:
		print(f"\n{Fore.LIGHTBLUE_EX}Event Types:")
		for event_type, count in summary['event_types'].items():
			print(f"  {Fore.CYAN}{event_type}: {Fore.YELLOW}{count}")
	
	if summary['top_actions']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Actions:")
		for action, count in summary['top_actions'].items():
			print(f"  {Fore.CYAN}{action}: {Fore.YELLOW}{count}")
	
	if summary['top_source_ips']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Source IPs:")
		for ip, count in summary['top_source_ips'].items():
			print(f"  {Fore.CYAN}{ip}: {Fore.YELLOW}{count}")
	
	if summary['top_dest_ips']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Destination IPs:")
		for ip, count in summary['top_dest_ips'].items():
			print(f"  {Fore.CYAN}{ip}: {Fore.YELLOW}{count}")
	
	if summary['top_devices']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Devices:")
		for device, count in summary['top_devices'].items():
			print(f"  {Fore.CYAN}{device}: {Fore.YELLOW}{count}")
	
	if summary['top_services']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Services:")
		for service, count in summary['top_services'].items():
			print(f"  {Fore.CYAN}{service}: {Fore.YELLOW}{count}")
	
	if summary['top_countries']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Countries:")
		for country, count in summary['top_countries'].items():
			print(f"  {Fore.CYAN}{country}: {Fore.YELLOW}{count}")
	
	if summary['top_modules']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Modules:")
		for module, count in summary['top_modules'].items():
			print(f"  {Fore.CYAN}{module}: {Fore.YELLOW}{count}")
	
	if summary['top_vservers']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Virtual Servers:")
		for vserver, count in summary['top_vservers'].items():
			print(f"  {Fore.CYAN}{vserver}: {Fore.YELLOW}{count}")
	
	if summary['top_destinations']:
		print(f"\n{Fore.LIGHTBLUE_EX}Top Destinations:")
		for dest, count in summary['top_destinations'].items():
			print(f"  {Fore.CYAN}{dest}: {Fore.YELLOW}{count}")
	
	if summary['traffic_stats']['total_bytes_received'] > 0 or summary['traffic_stats']['total_bytes_sent'] > 0:
		print(f"\n{Fore.LIGHTBLUE_EX}Traffic Statistics:")
		print(f"  {Fore.CYAN}Total Bytes Received: {Fore.YELLOW}{summary['traffic_stats']['total_bytes_received']:,}")
		print(f"  {Fore.CYAN}Total Bytes Sent: {Fore.YELLOW}{summary['traffic_stats']['total_bytes_sent']:,}")
		print(f"  {Fore.CYAN}Unique Sources: {Fore.YELLOW}{summary['traffic_stats']['unique_source_count']}")
		print(f"  {Fore.CYAN}Unique Destinations: {Fore.YELLOW}{summary['traffic_stats']['unique_destination_count']}")
	
	if summary['time_range']['earliest'] and summary['time_range']['latest']:
		print(f"\n{Fore.LIGHTBLUE_EX}Time Range:")
		print(f"  {Fore.CYAN}Earliest: {Fore.YELLOW}{summary['time_range']['earliest']}")
		print(f"  {Fore.CYAN}Latest: {Fore.YELLOW}{summary['time_range']['latest']}")
		print(f"  {Fore.CYAN}Total Events with Timestamps: {Fore.YELLOW}{summary['time_range']['count']}")
	
	print(f"{Style.RESET_ALL}")

if __name__ == '__main__':
	pass
