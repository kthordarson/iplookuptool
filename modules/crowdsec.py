from loguru import logger
import os
import aiohttp

CROWDSECAPIKEY = os.environ.get("CROWDSECAPIKEY")
if not CROWDSECAPIKEY:
	logger.warning("missing crowdsec api key")
	# os._exit(-1)

async def get_crowdsec_data(args):
	if CROWDSECAPIKEY:
		headers = {"x-api-key": CROWDSECAPIKEY}
		# curl -H "x-api-key: YOUR_API_KEY" https://cti.api.crowdsec.net/v2/smoke/185.7.214.104 | jq .
		try:
			async with aiohttp.ClientSession() as session:
				async with session.get(f"https://cti.api.crowdsec.net/v2/smoke/{args.host}", headers=headers) as response:
					if response.status == 200:
						try:
							jsonresp = await response.json()
						except Exception as e:
							logger.error(f"[!] {e} {type(e)} while parsing json response")
							return None
						if jsonresp:
							data = jsonresp
							return data
						else:
							logger.error(f"Unknown error for {args.host} json: {jsonresp}")
							return None
					elif response.status == 404:
						if args.debug:
							text = await response.text()
							logger.warning(f"[!] not found {args.host} {text}")  # type: ignore
						return None
					else:
						logger.warning(f"[!] {response.status} {response.reason} for {args.host}")
						if args.debug:
							logger.warning(f"headers: {response.headers}")
							logger.warning(f"text: {await response.text()}")
						return None
		except Exception as e:
			logger.error(f"[!] {e} {type(e)}")
			return None

crowdsectestdata = {
  "ip": "141.98.82.26",
  "reputation": "malicious",
  "ip_range": "141.98.82.0/23",
  "background_noise": "high",
  "confidence": "high",
  "background_noise_score": 10,
  "ip_range_score": 5,
  "as_name": "Flyservers S.A.",
  "as_num": 209588,
  "ip_range_24": "141.98.82.0/24",
  "ip_range_24_reputation": "suspicious",
  "ip_range_24_score": 3,
  "location": {
	"country": "PA",
	"city": "null",
	"latitude": 9.0,
	"longitude": -80.0
  },
  "reverse_dns": "null",
  "behaviors": [
	{
	  "name": "ssh:bruteforce",
	  "label": "SSH Bruteforce",
	  "description": "IP has been reported for performing brute force on ssh services.",
	  "references": []
	},
	{
	  "name": "http:scan",
	  "label": "HTTP Scan",
	  "description": "IP has been reported for performing actions related to HTTP vulnerability scanning and discovery.",
	  "references": []
	},
	{
	  "name": "http:exploit",
	  "label": "HTTP Exploit",
	  "description": "IP has been reported for attempting to exploit a vulnerability in a web application.",
	  "references": []
	},
	{
	  "name": "http:bruteforce",
	  "label": "HTTP Bruteforce",
	  "description": "IP has been reported for performing a HTTP brute force attack (either generic HTTP probing or applicative related brute force).",
	  "references": []
	},
	{
	  "name": "generic:exploit",
	  "label": "Exploitation attempt",
	  "description": "IP has been reported trying to exploit known vulnerability/CVE on unspecified protocols.",
	  "references": []
	},
	{
	  "name": "http:dos",
	  "label": "HTTP DoS",
	  "description": "IP has been reported trying to perform denial of service attacks.",
	  "references": []
	},
	{
	  "name": "http:crawl",
	  "label": "HTTP Crawl",
	  "description": "IP has been reported for performing aggressive crawling of web applications.",
	  "references": []
	},
	{
	  "name": "generic:scan",
	  "label": "Scan attempt",
	  "description": "IP has been reported trying to scan or gather information",
	  "references": []
	}
  ],
  "history": {
	"first_seen": "2025-07-07T02:00:00+00:00",
	"last_seen": "2025-09-10T05:00:00+00:00",
	"full_age": 67,
	"days_age": 66
  },
  "classifications": {
	"false_positives": [],
	"classifications": [
	  {
		"name": "profile:spoofed_user_agent",
		"label": "Spoofed User Agent",
		"description": "IP uses rapidly changing user agents.",
		"references": []
	  },
	  {
		"name": "community-blocklist",
		"label": "CrowdSec Community Blocklist",
		"description": "IP belongs to the CrowdSec Community Blocklist"
	  }
	]
  },
  "attack_details": [
	{
	  "name": "crowdsecurity/ssh-slow-bf",
	  "label": "SSH Slow Bruteforce",
	  "description": "Detect slow ssh bruteforce",
	  "references": []
	},
	{
	  "name": "crowdsecurity/crowdsec-appsec-outofband",
	  "label": "Triggered multiple OutOfBand CrowdSec AppSec rules",
	  "description": "IP has made more than 5 requests that triggered out-of-band appsec rules",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-4009",
	  "label": "3080ipx-10G - RCE",
	  "description": "3080ipx-10G - RCE (CVE-2025-4009)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/grafana-cve-2021-43798",
	  "label": "Grafana - LFI",
	  "description": "Grafana - Arbitrary File Read (CVE-2021-43798)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-cve-2021-42013",
	  "label": "CVE-2021-42013",
	  "description": "Apache - Path Traversal (CVE-2021-42013)",
	  "references": []
	},
	{
	  "name": "baudneo/zoneminder_cve-2022-39290",
	  "label": "Zoneminder CVE-2022-39290",
	  "description": "Detect cve-2022-39290 exploitation attempts",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-sensitive-files",
	  "label": "Access to sensitive files over HTTP",
	  "description": "Detect attempt to access to sensitive files (.log, .db ..) or folders (.git)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2024-7399",
	  "label": "MagicINFO 9 Server - Path Traversal",
	  "description": "MagicINFO 9 Server - Path Traversal (CVE-2024-7399)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2023-22518",
	  "label": "Atlassian Confluence Server CVE-2023-22518",
	  "description": "Detect CVE-2023-22518 exploits",
	  "references": []
	},
	{
	  "name": "crowdsecurity/endlessh-bf",
	  "label": "Endlessh Bruteforce",
	  "description": "Detect SSH bruteforce caught by Endlessh",
	  "references": []
	},
	{
	  "name": "crowdsecurity/nextcloud-bf_domain_error",
	  "label": "NextCloud Bruteforce",
	  "description": "Detect Nextcloud domain error",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2024-3400",
	  "label": "PAN-OS - RCE",
	  "description": "PAN-OS - RCE (CVE-2024-3400)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2021-41773",
	  "label": "Apache HTTP Server - Path Traversal",
	  "description": "Apache HTTP Server - Path Traversal (CVE-2021-41773)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CNVD-2021-33202",
	  "label": "e-cology OA - SQLi",
	  "description": "e-cology OA - SQLi (CNVD-2021-33202)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-30406",
	  "label": "CentreStack - RCE",
	  "description": "CentreStack - RCE (CVE-2025-30406)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/suricata-major-severity",
	  "label": "Suricata Severity 1 Event",
	  "description": "Detect exploit attempts via emerging threat rules",
	  "references": []
	},
	{
	  "name": "crowdsecurity/netgear_rce_setup_cgi",
	  "label": "Netgear - Unauthenticated RCE (setup.cgi)",
	  "description": "Netgear DGN1000/DGN220 Unauthenticated RCE via setup.cgi",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-bad-user-agent",
	  "label": "Bad User Agent",
	  "description": "Detect usage of bad User Agent",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-open-proxy",
	  "label": "HTTP Open Proxy Probing",
	  "description": "Detect scan for open proxy",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-admin-interface-probing",
	  "label": "HTTP Admin Interface Probing",
	  "description": "Detect generic HTTP admin interface probing",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2024-7029",
	  "label": "Chamilo - SQLi",
	  "description": "Chamilo - SQLi (CVE-2024-7029)",
	  "references": []
	},
	{
	  "name": "LePresidente/http-generic-401-bf",
	  "label": "HTTP Bruteforce",
	  "description": "Detect generic 401 Authorization error brute force",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2024-20439",
	  "label": "Cisco smart license utility - Authentication Bypass",
	  "description": "Cisco smart license utility - Authentication Bypass (CVE-2024-20439)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2022-46169-cmd",
	  "label": "Cacti CVE-2022-46169",
	  "description": "Detect CVE-2022-46169 cmd injection",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-wordpress_wpconfig",
	  "label": "Access to WordPress wp-config.php",
	  "description": "Detect WordPress probing: variations around wp-config.php by wpscan",
	  "references": []
	},
	{
	  "name": "crowdsecurity/appsec-vpatch",
	  "label": "Blocked by CrowdSec AppSec",
	  "description": "Identify attacks flagged by CrowdSec AppSec",
	  "references": []
	},
	{
	  "name": "crowdsecurity/modsecurity",
	  "label": "Modsecurity Alert",
	  "description": "Web exploitation via modsecurity",
	  "references": []
	},
	{
	  "name": "crowdsecurity/wordpress_wpconfig_scan",
	  "label": "Wordpress wpconfig scan",
	  "description": "Detect WordPress wpconfig scan",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-cve-2021-41773",
	  "label": "CVE-2021-41773",
	  "description": "Apache - Path Traversal (CVE-2021-41773)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-31324",
	  "label": "SAP NetWeaver - RCE",
	  "description": "SAP NetWeaver - RCE (CVE-2025-31324)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-probing",
	  "label": "HTTP Probing",
	  "description": "Detect site scanning/probing from a single ip",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2020-5902",
	  "label": "F5 BIG-IP TMUI - RCE",
	  "description": "F5 BIG-IP TMUI - RCE (CVE-2020-5902)",
	  "references": []
	},
	{
	  "name": "barnoux/crs-anomaly-score",
	  "label": "CRS Anomaly Alert",
	  "description": "Web exploitation detected via Core Rule Set inbound anomaly scoring set by the user in crs-setup.conf",
	  "references": []
	},
	{
	  "name": "crowdsecurity/netgear_rce",
	  "label": "Netgear RCE",
	  "description": "Detect Netgear RCE DGN1000/DGN220 exploitation attempts",
	  "references": []
	},
	{
	  "name": "openappsec/openappsec-rce",
	  "label": "Openappsec 'rce' detection",
	  "description": "Detect openappsec 'prevent' securityActions on 'Remote Code Execution' events (when waf blocks malicious request)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/ssh-bf",
	  "label": "SSH Bruteforce",
	  "description": "Detect ssh bruteforce",
	  "references": []
	},
	{
	  "name": "crowdsecurity/ognl_injection",
	  "label": "OGNL Injection",
	  "description": "OGNL Injection exploitation",
	  "references": []
	},
	{
	  "name": "crowdsecurity/apache_log4j2_cve-2021-44228",
	  "label": "Log4j CVE-2021-44228",
	  "description": "Detect cve-2021-44228 exploitation attemps",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-3248",
	  "label": "Langflow - RCE",
	  "description": "Langflow - RCE (CVE-2025-3248)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/fortinet-cve-2022-40684",
	  "label": "Fortinet CVE-2022-40684",
	  "description": "Detect cve-2022-40684 exploitation attempts",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-dos-invalid-http-versions",
	  "label": "HTTP DOS with invalid HTTP version",
	  "description": "Detect DoS tools using invalid HTTP versions",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-crawl-non_statics",
	  "label": "Aggressive Crawl",
	  "description": "Detect aggressive crawl on non static resources",
	  "references": []
	},
	{
	  "name": "openappsec/openappsec-probing",
	  "label": "Openappsec 'probing' detection",
	  "description": "Detect openappsec 'prevent' securityActions on 'Vulnerability Scanning' events (when waf blocks malicious request)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/f5-big-ip-cve-2020-5902",
	  "label": "F5 BIG-IP TMUI - RCE",
	  "description": "F5 BIG-IP TMUI - RCE (CVE-2020-5902)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2021-44228",
	  "label": "Apache Log4j2 - RCE",
	  "description": "Apache Log4j2 - RCE (CVE-2021-44228)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/generic-phpinfo",
	  "label": "Generic PHP Info Detection",
	  "description": "Detect phpinfo access attempts",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-20188",
	  "label": "Cisco IOS XE Software - Hardcoded Credentials",
	  "description": "Cisco IOS XE Software - Hardcoded Credentials (CVE-2025-20188)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2022-40684",
	  "label": "FortiOS - Authentication Bypass",
	  "description": "FortiOS - Authentication Bypass (CVE-2022-40684)",
	  "references": []
	},
	{
	  "name": "openappsec/openappsec-path-traversal",
	  "label": "Openappsec 'path traversal' detection",
	  "description": "Detect openappsec 'prevent' securityActions on 'Path Traversal' events (when waf blocks malicious request)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/vpatch-CVE-2025-31161",
	  "label": "CrushFTP - Authentication Bypass",
	  "description": "Detects authentication bypass in CrushFTP via crafted Authorization header and specific endpoint access.",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-path-traversal-probing",
	  "label": "HTTP Path Traversal Exploit",
	  "description": "Detect path traversal attempt",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2023-22515",
	  "label": "Confluence CVE-2023-22515",
	  "description": "Detect CVE-2023-22515 exploitation",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2024-0012",
	  "label": "CVE-2024-0012",
	  "description": "Detect CVE-2024-0012 exploitation attempts",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-31161",
	  "label": "CrushFTP - Authentication Bypass",
	  "description": "CrushFTP - Authentication Bypass (CVE-2025-31161)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/postfix-non-smtp-command",
	  "label": "Postfix Non-SMTP Command",
	  "description": "Detect scanning of postfix service through non-SMTP commands",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-32813",
	  "label": "Infoblox NETMRI - RCE",
	  "description": "Infoblox NETMRI - RCE (CVE-2025-32813)",
	  "references": []
	},
	{
	  "name": "openappsec/openappsec-xss",
	  "label": "Openappsec 'XSS' detection",
	  "description": "Detect openappsec 'prevent' securityActions on 'Cross Site Scripting' events (when waf blocks malicious request)",
	  "references": []
	},
	{
	  "name": "LePresidente/http-generic-403-bf",
	  "label": "HTTP Bruteforce",
	  "description": "Detect generic 403 Forbidden (Authorization) error brute force",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-0107",
	  "label": "Cloud NGFW - RCE",
	  "description": "Cloud NGFW - RCE (CVE-2025-0107)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2022-26134",
	  "label": "Confluence - RCE",
	  "description": "Confluence - RCE (CVE-2022-26134)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/spring4shell_cve-2022-22965",
	  "label": "Spring4shell CVE-2022-22965",
	  "description": "Detect cve-2022-22965 probing",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-54309",
	  "label": "CrushFTP - Authentication Bypass",
	  "description": "CrushFTP - Authentication Bypass (CVE-2025-54309)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/nginx-req-limit-exceeded",
	  "label": "Nginx request limit exceeded",
	  "description": "Detects IPs which violate nginx's user set request limit.",
	  "references": []
	},
	{
	  "name": "crowdsecurity/vpatch-CVE-2025-3248",
	  "label": "Langflow - RCE",
	  "description": "Detects unauthenticated remote code execution in Langflow via /api/v1/validate/code endpoint.",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-dos-swithcing-ua",
	  "label": "HTTP DOS with varying UA",
	  "description": "Detect DoS tools switching user-agent too fast",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-34300",
	  "label": "Lighthouse Studio - RCE",
	  "description": "Lighthouse Studio - RCE (CVE-2025-34300)",
	  "references": []
	},
	{
	  "name": "openappsec/openappsec-evasion-techniques",
	  "label": "Openappsec 'Evasion Techniques' detection",
	  "description": "Detect openappsec 'prevent' securityActions on 'Evasion Techniques' events (when waf blocks malicious request)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2025-29306",
	  "label": "FoxCMS - RCE",
	  "description": "FoxCMS - RCE (CVE-2025-29306)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2022-35914",
	  "label": "GLPI CVE-2022-35914",
	  "description": "Detect CVE-2022-35914 exploits",
	  "references": []
	},
	{
	  "name": "crowdsecurity/generic-backdoors",
	  "label": "Scanning for backdoors",
	  "description": "Detect attempt to common backdoors",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2024-4040",
	  "label": "CrushFTP - Sandbox Escape",
	  "description": "CrushFTP - Sandbox Escape (CVE-2024-4040)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/appsec-native",
	  "label": "Blocked by CrowdSec AppSec",
	  "description": "Identify attacks flagged by CrowdSec AppSec via native rules",
	  "references": []
	},
	{
	  "name": "crowdsecurity/generic-wordpress-uploads-php",
	  "label": "Detect Wordpress PHP execution in uploads directory",
	  "description": "Detect php execution in wordpress uploads directory",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2021-26294",
	  "label": "AfterLogic Aurora - Directory Traversal",
	  "description": "AfterLogic Aurora - Directory Traversal (CVE-2021-26294)",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-cve-probing",
	  "label": "HTTP CVE Probing",
	  "description": "Detect generic HTTP cve probing",
	  "references": []
	},
	{
	  "name": "crowdsecurity/vpatch-CVE-2025-29306",
	  "label": "FoxCMS - RCE",
	  "description": "Detects FoxCMS v1.2.5 RCE via malicious id parameter in /images/index.html",
	  "references": []
	},
	{
	  "name": "crowdsecurity/http-wordpress-scan",
	  "label": "WordPress Vuln Hunting",
	  "description": "Detect exploitation attempts against common WordPress endpoints",
	  "references": []
	},
	{
	  "name": "crowdsecurity/CVE-2017-9841",
	  "label": "PHP Unit Test Framework CVE-2017-9841",
	  "description": "Detect CVE-2017-9841 exploits",
	  "references": []
	}
  ],
  "target_countries": {
	"DE": 47,
	"FR": 25,
	"US": 6,
	"AT": 4,
	"FI": 3,
	"NL": 3,
	"IT": 3,
	"GB": 2,
	"CH": 2,
	"PL": 1
  },
  "mitre_techniques": [
	{
	  "name": "T1110",
	  "label": "Brute Force",
	  "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
	  "references": []
	},
	{
	  "name": "T1190",
	  "label": "Exploit Public-Facing Application",
	  "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
	  "references": []
	},
	{
	  "name": "T1595",
	  "label": "Active Scanning",
	  "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
	  "references": []
	},
	{
	  "name": "T1548",
	  "label": "Abuse Elevation Control Mechanism",
	  "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions.",
	  "references": []
	},
	{
	  "name": "T1498",
	  "label": "Network Denial of Service",
	  "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.",
	  "references": []
	},
	{
	  "name": "T1189",
	  "label": "Drive-by Compromise",
	  "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.",
	  "references": []
	}
  ],
  "cves": [
	"CVE-2024-7399",
	"CVE-2025-20188",
	"CVE-2022-22965",
	"CVE-2025-4009",
	"CVE-2025-54309",
	"CVE-2022-35914",
	"CVE-2024-20439",
	"CVE-2025-0107",
	"CVE-2022-46169",
	"CVE-2023-22518",
	"CVE-2025-31324",
	"CVE-2024-12847",
	"CVE-2022-26134",
	"CVE-2021-41773",
	"CVE-2021-42013",
	"CVE-2024-3400",
	"CVE-2017-9841",
	"CVE-2021-26294",
	"CVE-2024-0012",
	"CVE-2022-39290",
	"CVE-2012-0392",
	"CVE-2021-44228",
	"CVE-2022-40684",
	"CVE-2020-5902",
	"CVE-2021-43798",
	"CVE-2025-29306",
	"CVE-2025-34300",
	"CVE-2024-7029",
	"CVE-2025-32813",
	"CVE-2023-22515",
	"CVE-2024-4040",
	"CVE-2025-30406",
	"CVE-2025-31161",
	"CVE-2025-3248"
  ],
  "scores": {
	"overall": {
	  "aggressiveness": 5,
	  "threat": 3,
	  "trust": 5,
	  "anomaly": 1,
	  "total": 4
	},
	"last_day": {
	  "aggressiveness": 5,
	  "threat": 3,
	  "trust": 5,
	  "anomaly": 1,
	  "total": 4
	},
	"last_week": {
	  "aggressiveness": 5,
	  "threat": 3,
	  "trust": 5,
	  "anomaly": 1,
	  "total": 4
	},
	"last_month": {
	  "aggressiveness": 5,
	  "threat": 3,
	  "trust": 5,
	  "anomaly": 1,
	  "total": 4
	}
  },
  "references": [
	{
	  "name": "list:crowdsec_intelligence_blocklist",
	  "label": "CrowdSec Intelligence Blocklist",
	  "description": "CrowdSec's main blocklist, containing the most aggressive IPs identified as attacking our network. It is a core anti-bot, mass attack list you should subscribe to in priority.",
	  "references": []
	},
	{
	  "name": "list:crowdsec_high_background_noise",
	  "label": "High Background Noise",
	  "description": "Contains IPs considered internet background noise, identified as malicious or potential threats. Blocking these IPs can reduce further your alert volume and save infrastructure resources.",
	  "references": []
	}
  ]
}