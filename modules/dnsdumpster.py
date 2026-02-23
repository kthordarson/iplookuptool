import os
import aiohttp
from loguru import logger
import base64
import html
import json
import re
from typing import Any, Dict, List, Optional
import requests
from bs4 import BeautifulSoup, Tag
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.SSLError)  # type: ignore

async def get_dnsdumpster(args):
	"""
	Query dnsdumpster.com API for IP.

	args:
		args

	Returns:
		dict: Geolocation data or None if error
	"""
	api_key = os.environ.get("DNSDUMPSTER_APIKEY")
	base_url = "https://dnsdumpster.com"
	if not api_key:
		logger.warning("missing dnsdumpster.com api key")
	else:
		url = "https://api.dnsdumpster.com/htmld/"
		headers = {
			"accept": "application/json",
			"Referer": base_url,
			"Origin": base_url,
			"Authorization": api_key,
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		}
		data = {"target": str(args.ip)}
		try:
			async with aiohttp.ClientSession() as session:
				session.headers.update(headers)
				async with session.post(url, json=data) as response:
					if response.status == 200:
						data = await response.text()
						return data
					else:
						logger.error(f"dnsdumpster error: {response.status} {response.reason} for {args.ip}")
						return None
		except Exception as e:
			logger.error(f"dnsdumpster exception: {e} {type(e)} for {args.ip}")
			return None

class DNSDumpsterAPIError(Exception):
	"""Base exception for DNSDumpster API errors."""

	pass

class DNSDumpsterRequestError(DNSDumpsterAPIError):
	"""Exception raised when HTTP request fails."""

	pass

class DNSDumpsterParseError(DNSDumpsterAPIError):
	"""Exception raised when parsing response fails."""

	pass

class DNSDumpsterAPI:
	BASE_URL = "https://dnsdumpster.com/"
	API_URL = "https://api.dnsdumpster.com/htmld/"

	def __init__(self, session: Optional[requests.Session] = None):
		"""Initialize the DNSDumpster API client."""
		self.session = session if session is not None else requests.Session()

	@staticmethod
	def _extract_ip_address(td: Tag) -> str:
		"""
		Extract IP address from a table cell.

		Args:
			td: BeautifulSoup Tag object representing a table cell.

		Returns:
			IP address as string, or empty string if not found.
		"""
		pattern_ip = r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
		ip_matches = re.findall(pattern_ip, td.get_text())
		return ip_matches[0] if ip_matches else ""

	@staticmethod
	def _extract_reverse_dns(td: Tag) -> str:
		"""
		Extract reverse DNS from a table cell.

		Args:
			td: BeautifulSoup Tag object representing a table cell.

		Returns:
			Reverse DNS as string, or empty string if not found.
		"""
		reverse_dns_span = td.find("span", class_="xs-text")
		return reverse_dns_span.get_text(strip=True) if reverse_dns_span else ""

	@staticmethod
	def _extract_asn(td: Tag) -> str:
		"""
		Extract ASN (Autonomous System Number) from a table cell.

		Args:
			td: BeautifulSoup Tag object representing a table cell.

		Returns:
			ASN as string with 'ASN:' prefix, or empty string if not found.
		"""
		asn_text = td.get_text(separator="|", strip=True)
		asn_match = re.search(r"ASN:(\d+)", asn_text)
		return "ASN:" + asn_match.group(1) if asn_match else ""

	@staticmethod
	def _extract_subnet(td: Tag) -> str:
		"""
		Extract subnet information from a table cell.

		Args:
			td: BeautifulSoup Tag object representing a table cell.

		Returns:
			Subnet as string, or empty string if not found.
		"""
		subnet_span = td.find("span", class_="sm-text")
		return subnet_span.get_text(strip=True) if subnet_span else ""

	@staticmethod
	def _extract_country(td: Tag) -> str:
		"""
		Extract country information from a table cell.

		Args:
			td: BeautifulSoup Tag object representing a table cell.

		Returns:
			Country as string, or empty string if not found.
		"""
		country_span = td.find("span", class_="light-text")
		return country_span.get_text(strip=True) if country_span else ""

	@staticmethod
	def _extract_asn_name(td: Tag, country: str) -> str:
		"""
		Extract ASN name/provider from a table cell.

		Args:
			td: BeautifulSoup Tag object representing a table cell.
			country: Country string to remove from the text.

		Returns:
			ASN name/provider as string, or empty string if not found.
		"""
		provider_text = td.get_text(separator="|", strip=True)
		asn_name = provider_text.replace(country, "").replace("|", " ").strip()
		return asn_name

	def _parse_common_columns(self, tds: List[Tag], start_col: int = 1) -> Dict[str, str]:
		"""
		Parse common columns (IP, ASN, Country) that appear in most record types.

		Args:
			tds: List of table cell Tags.
			start_col: Starting column index for IP column (default 1).

		Returns:
			Dictionary with parsed common fields.
		"""
		data: Dict[str, str] = {}

		try:
			# IP and Reverse DNS column
			if len(tds) > start_col and tds[start_col]:
				ip_column = tds[start_col]
				data["ip"] = self._extract_ip_address(ip_column)
				data["reverse_dns"] = self._extract_reverse_dns(ip_column)
			else:
				data["ip"] = ""
				data["reverse_dns"] = ""

			# ASN and Subnet column
			if len(tds) > start_col + 1 and tds[start_col + 1]:
				asn_column = tds[start_col + 1]
				data["asn"] = self._extract_asn(asn_column)
				data["subnet"] = self._extract_subnet(asn_column)
			else:
				data["asn"] = ""
				data["subnet"] = ""

			# Provider and Country column
			if len(tds) > start_col + 2 and tds[start_col + 2]:
				provider_column = tds[start_col + 2]
				data["country"] = self._extract_country(provider_column)
				data["asn_name"] = self._extract_asn_name(provider_column, data["country"])
			else:
				data["asn_name"] = ""
				data["country"] = ""

		except Exception as e:
			logger.debug(f"Error parsing common columns: {e}")
			# Return partial data on error

		return data

	def retrieve_results(self, table: Tag) -> List[Dict[str, str]]:
		"""
		Extract A Records (subdomains) from an HTML table.

		Args:
			table: BeautifulSoup Tag object representing the table.

		Returns:
			List of dictionaries containing subdomain information with keys:
			- host: Hostname/subdomain
			- ip: IP address
			- reverse_dns: Reverse DNS lookup
			- asn: Autonomous System Number
			- asn_name: ASN provider name
			- country: Country code/name
			- subnet: Subnet information
			- open_services: Open services/ports (if available)
			- domain: Alias for 'host' (backward compatibility)
			- as: Alias for 'asn' (backward compatibility)
			- provider: Alias for 'asn_name' (backward compatibility)
		"""
		res: List[Dict[str, str]] = []
		trs = table.find_all("tr")

		for tr in trs:
			tds = tr.find_all("td")

			# Skip header rows or rows without enough columns
			if len(tds) < 4:
				continue

			try:
				data: Dict[str, str] = {}

				# Column 1: Host/Domain
				data["host"] = tds[0].get_text(strip=True) if tds[0] else ""

				# Parse common columns (IP, ASN, Country, etc.)
				common_data = self._parse_common_columns(tds, start_col=1)
				data.update(common_data)

				# Column 5: Open Services (if exists)
				if len(tds) >= 5 and tds[4]:
					services_text = tds[4].get_text(strip=True)
					data["open_services"] = services_text if services_text else ""
				else:
					data["open_services"] = ""

				# Add backward-compatible keys
				data["domain"] = data["host"]
				data["as"] = data["asn"]
				data["provider"] = data["asn_name"]

				# Only add if we have at least a host or IP
				if data["host"] or data["ip"]:
					res.append(data)

			except Exception as e:
				logger.debug(f"Error parsing A record row: {e}")
				continue

		return res

	def retrieve_mx_records(self, table: Tag) -> List[Dict[str, str]]:
		"""
		Extract MX (Mail Exchange) Records from an HTML table.

		Args:
			table: BeautifulSoup Tag object representing the table.

		Returns:
			List of dictionaries containing MX record information with keys:
			- priority: MX priority value
			- server: Mail server hostname
			- ip: IP address
			- reverse_dns: Reverse DNS lookup
			- asn: Autonomous System Number
			- asn_name: ASN provider name
			- country: Country code/name
			- subnet: Subnet information
			- domain: Alias for 'server' (backward compatibility)
			- as: Alias for 'asn' (backward compatibility)
			- provider: Alias for 'asn_name' (backward compatibility)
		"""
		res: List[Dict[str, str]] = []
		trs = table.find_all("tr")

		for tr in trs:
			tds = tr.find_all("td")

			# Skip header rows or rows without enough columns
			if len(tds) < 4:
				continue

			try:
				data: Dict[str, str] = {}

				# Column 1: Priority and Server (e.g., "10 mail.example.com")
				if tds[0]:
					mx_text = tds[0].get_text(strip=True)
					mx_parts = mx_text.split(None, 1)  # Split on first whitespace
					if len(mx_parts) >= 2:
						data["priority"] = mx_parts[0]
						data["server"] = mx_parts[1]
					elif len(mx_parts) == 1:
						data["priority"] = ""
						data["server"] = mx_parts[0]
					else:
						data["priority"] = ""
						data["server"] = mx_text
				else:
					data["priority"] = ""
					data["server"] = ""

				# Parse common columns
				common_data = self._parse_common_columns(tds, start_col=1)
				data.update(common_data)

				# Add backward-compatible keys
				data["domain"] = data["server"]
				data["as"] = data["asn"]
				data["provider"] = data["asn_name"]

				# Only add if we have at least a server or IP
				if data["server"] or data["ip"]:
					res.append(data)

			except Exception as e:
				logger.debug(f"Error parsing MX record row: {e}")
				continue

		return res

	def retrieve_ns_records(self, table: Tag) -> List[Dict[str, str]]:
		"""
		Extract NS (Name Server) Records from an HTML table.

		Args:
			table: BeautifulSoup Tag object representing the table.

		Returns:
			List of dictionaries containing NS record information with keys:
			- nameserver: Nameserver hostname
			- ip: IP address
			- reverse_dns: Reverse DNS lookup
			- asn: Autonomous System Number
			- asn_name: ASN provider name
			- country: Country code/name
			- subnet: Subnet information
			- domain: Alias for 'nameserver' (backward compatibility)
			- as: Alias for 'asn' (backward compatibility)
			- provider: Alias for 'asn_name' (backward compatibility)
		"""
		res: List[Dict[str, str]] = []
		trs = table.find_all("tr")

		for tr in trs:
			tds = tr.find_all("td")

			# Skip header rows or rows without enough columns
			if len(tds) < 4:
				continue

			try:
				data: Dict[str, str] = {}

				# Column 1: Nameserver
				data["nameserver"] = tds[0].get_text(strip=True) if tds[0] else ""

				# Parse common columns
				common_data = self._parse_common_columns(tds, start_col=1)
				data.update(common_data)

				# Add backward-compatible keys
				data["domain"] = data["nameserver"]
				data["as"] = data["asn"]
				data["provider"] = data["asn_name"]

				# Only add if we have at least a nameserver or IP
				if data["nameserver"] or data["ip"]:
					res.append(data)

			except Exception as e:
				logger.debug(f"Error parsing NS record row: {e}")
				continue

		return res

	def retrieve_txt_record(self, table: Tag) -> List[str]:
		"""
		Extract TXT Records from an HTML table.

		Args:
			table: BeautifulSoup Tag object representing the table.

		Returns:
			List of text content from each table cell.
		"""
		res: List[str] = []

		try:
			trs = table.find_all("tr")
			for tr in trs:
				tds = tr.find_all("td")
				for td in tds:
					text = td.get_text(strip=True)
					if text:
						res.append(text)
		except Exception as e:
			logger.debug(f"Error parsing TXT records: {e}")

		return res

	def find_table_by_heading(self, soup: BeautifulSoup, heading_text: str) -> Optional[Tag]:
		"""
		Find an HTML table by looking for a preceding paragraph tag with specific text.

		Args:
			soup: BeautifulSoup object representing the HTML document.
			heading_text: Text to search for in paragraph tags.

		Returns:
			BeautifulSoup Tag object representing the table, or None if not found.
		"""
		try:
			# Find all paragraph tags
			paragraphs = soup.find_all("p")

			for p in paragraphs:
				# Check if this paragraph contains the heading text
				if heading_text.lower() in p.get_text(strip=True).lower():
					# Find the next table after this paragraph
					next_table = p.find_next("table")
					if next_table:
						return next_table
		except Exception as e:
			logger.debug(f'Error finding table for heading "{heading_text}": {e}')

		return None

	def _get_authorization_token(self) -> str:
		"""
		Retrieve authorization token from DNSDumpster main page.

		Returns:
			Authorization token string.

		Raises:
			DNSDumpsterRequestError: If unable to retrieve the token.
		"""
		try:
			req = self.session.get(self.BASE_URL, verify=False)
			req.raise_for_status()

			soup = BeautifulSoup(req.content, "html.parser")
			form = soup.find("form", attrs={"data-form-id": "mainform"})

			hx_headers = form.get("hx-headers")  # type: ignore

			unescaped = html.unescape(hx_headers)  # type: ignore
			headers_dict = json.loads(unescaped)
			auth_token = headers_dict.get("Authorization")

			if not auth_token:
				raise DNSDumpsterParseError("Could not extract authorization token")

			logger.debug(f"Retrieved access token: {auth_token}")
			return auth_token

		except requests.RequestException as e:
			raise DNSDumpsterRequestError(f"Failed to retrieve authorization token: {e}")
		except (ValueError, json.JSONDecodeError) as e:
			raise DNSDumpsterParseError(f"Failed to parse authorization token: {e}")

	def search(self, domain: str) -> Dict[str, Any]:
		"""
		Search for DNS records and subdomains for a given domain.

		This method queries dnsdumpster.com and retrieves:
		- A Records (subdomains)
		- MX Records (mail servers)
		- NS Records (name servers)
		- TXT Records
		- Network mapping image
		- Excel file with detailed results

		Args:
			domain: The domain name to search for (e.g., 'example.com').

		Returns:
			Dictionary containing:
			- domain: The queried domain
			- dns_records: Dictionary with 'dns', 'mx', 'ns', 'txt', 'host' keys
			- image_data: Base64 encoded network map image (or None)
			- image_url: URL to the network map image (or None)
			- xls_data: Base64 encoded Excel file (or None)
			- xls_url: URL to the Excel file (or None)

		Raises:
			DNSDumpsterRequestError: If HTTP request fails.
			DNSDumpsterParseError: If parsing the response fails.
		"""
		# Get authorization token
		try:
			auth_token = self._get_authorization_token()
		except Exception as e:
			logger.error(f'[!] {e} {type(e)} while retrieving authorization token')
			auth_token = ""  # Proceed without token, but likely to fail or return limited results

		# Prepare request headers and data
		headers = {
			"Referer": self.BASE_URL,
			"Origin": self.BASE_URL,
			"Authorization": auth_token,
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		}
		data = {"target": domain}

		# Make the search request
		try:
			req = self.session.post(self.API_URL, data=data, headers=headers, verify=False)

			if req.status_code != 200:
				raise DNSDumpsterRequestError(f"Unexpected status code from {self.API_URL}: {req.status_code}")

			content = req.content.decode("utf-8")
			if "There was an error getting results" in content:
				raise DNSDumpsterAPIError("There was an error getting results from DNSDumpster")

		except requests.RequestException as e:
			raise DNSDumpsterRequestError(f"Failed to perform search: {e}")

		# Parse the response
		soup = BeautifulSoup(req.content, "html.parser")

		res: Dict[str, Any] = {"domain": domain, "dns_records": {}}

		# Parse DNS records
		res["dns_records"] = self._parse_dns_records(soup)

		# Retrieve network map image
		res["image_data"], res["image_url"] = self._retrieve_image(soup, domain)

		# Retrieve Excel file
		res["xls_data"], res["xls_url"] = self._retrieve_excel(soup, domain, req.content.decode("utf-8"))

		return res

	def _parse_dns_records(self, soup: BeautifulSoup) -> Dict[str, List]:
		"""
		Parse all DNS record types from the HTML soup.

		Args:
			soup: BeautifulSoup object representing the response HTML.

		Returns:
			Dictionary with keys 'dns', 'mx', 'ns', 'txt', 'host' containing parsed records.
		"""
		dns_records: Dict[str, List] = {}

		# Find tables by their heading paragraphs
		a_records_table = self.find_table_by_heading(soup, "A Records") or self.find_table_by_heading(
			soup, "subdomains from dataset"
		)
		mx_records_table = self.find_table_by_heading(soup, "MX Records")
		ns_records_table = self.find_table_by_heading(soup, "NS Records")
		txt_records_table = self.find_table_by_heading(soup, "TXT Records")

		# Parse A Records (DNS/subdomains)
		if a_records_table:
			dns_records["dns"] = self.retrieve_results(a_records_table)
			logger.debug(f'Found {len(dns_records["dns"])} A records')
		else:
			dns_records["dns"] = []
			logger.debug("No A records table found")

		# Parse MX Records
		if mx_records_table:
			dns_records["mx"] = self.retrieve_mx_records(mx_records_table)
			logger.debug(f'Found {len(dns_records["mx"])} MX records')
		else:
			dns_records["mx"] = []
			logger.debug("No MX records table found")

		# Parse NS Records
		if ns_records_table:
			dns_records["ns"] = self.retrieve_ns_records(ns_records_table)
			logger.debug(f'Found {len(dns_records["ns"])} NS records')
		else:
			dns_records["ns"] = []
			logger.debug("No NS records table found")

		# Parse TXT Records
		if txt_records_table:
			dns_records["txt"] = self.retrieve_txt_record(txt_records_table)
			logger.debug(f'Found {len(dns_records["txt"])} TXT records')
		else:
			dns_records["txt"] = []
			logger.debug("No TXT records table found")

		# For backward compatibility, also store NS records as 'host'
		dns_records["host"] = dns_records["ns"]

		return dns_records

	def _retrieve_image(self, soup: BeautifulSoup, domain: str) -> tuple[Optional[bytes], Optional[str]]:
		"""
		Retrieve the network mapping image.

		Args:
			soup: BeautifulSoup object representing the response HTML.
			domain: The queried domain.

		Returns:
			Tuple of (base64 encoded image data, image URL).
			Both can be None if retrieval fails.
		"""
		image_data = None
		image_url = None

		try:
			logo_img = soup.find("img", alt="Logo")
			if logo_img and logo_img.get("src"):
				image_url = logo_img.get("src")
				# If it's a relative URL, make it absolute
				if image_url.startswith("/"):  # type: ignore
					image_url = "https://dnsdumpster.com" + image_url  # type: ignore
				elif not image_url.startswith("http"):  # type: ignore
					image_url = "https://dnsdumpster.com/" + image_url  # type: ignore

				logger.debug(f"Found image URL: {image_url}")
				image_data = base64.b64encode(self.session.get(image_url, verify=False).content)  # type: ignore
			else:
				# Fallback to old method
				logger.debug("Logo img not found, trying fallback method")
				tmp_url = f"https://dnsdumpster.com/static/map/{domain}.png"
				image_data = base64.b64encode(self.session.get(tmp_url, verify=False).content)
				image_url = tmp_url
		except Exception as e:
			logger.debug(f"Error retrieving image: {e}")

		return image_data, image_url  # type: ignore

	def _retrieve_excel(self, soup: BeautifulSoup, domain: str, content: str) -> tuple[Optional[bytes], Optional[str]]:
		"""
		Retrieve the Excel file with detailed results.

		Args:
			soup: BeautifulSoup object representing the response HTML.
			domain: The queried domain.
			content: Raw HTML content as string.

		Returns:
			Tuple of (base64 encoded Excel data, Excel URL).
			Both can be None if retrieval fails.
		"""
		xls_data = None
		xls_url = None

		try:
			# Find the download link
			download_links = soup.find_all("a")
			for link in download_links:
				link_text = link.get_text(strip=True).lower()
				if "download" in link_text and "xlsx" in link_text:
					xls_url = link.get("href")
					if xls_url:
						# If it's a relative URL, make it absolute
						if xls_url.startswith("/"):  # type: ignore
							xls_url = "https://dnsdumpster.com" + xls_url  # type: ignore
						elif not xls_url.startswith("http"):  # type: ignore
							xls_url = "https://dnsdumpster.com/" + xls_url  # type: ignore

						logger.debug(f"Found Excel URL: {xls_url}")
						xls_data = base64.b64encode(self.session.get(xls_url, verify=False).content)  # type: ignore
						break

			# Fallback to pattern matching if the link wasn't found
			if not xls_url:
				logger.debug("Download link not found, trying fallback method")
				pattern = r"/static/xlsx/" + re.escape(domain) + r"-[a-f0-9\-]{36}\.xlsx"
				xls_matches = re.findall(pattern, content)
				if xls_matches:
					xls_url = "https://dnsdumpster.com" + xls_matches[0]
					xls_data = base64.b64encode(self.session.get(xls_url, verify=False).content)
		except Exception as err:
			logger.error(f"Error retrieving Excel file: {err}")

		return xls_data, xls_url  # type: ignore

class DNSDumpsterClient:
	"""Client for interacting with the DNSDumpster API."""

	BASE_URL = "https://api.dnsdumpster.com"
	
	def __init__(self, rate_limit: float = 2.0):
		"""
		Initialize DNSDumpster client.

		Args:
			rate_limit: Minimum seconds between requests (default: 2.0)
		"""
		self.api_key = os.environ.get("DNSDUMPSTER_APIKEY")
		self.rate_limit = rate_limit
		self.last_request_time = 0
		self.session = requests.Session()
		headers = {'X-API-Key': self.api_key, 'User-Agent': 'Temenos/1.0'}
		self.session.headers.update(headers)

	def _wait_for_rate_limit(self):
		"""Ensure we respect the rate limit between requests."""
		current_time = time.time()
		time_since_last = current_time - self.last_request_time

		if time_since_last < self.rate_limit:
			sleep_time = self.rate_limit - time_since_last
			time.sleep(sleep_time)

		self.last_request_time = time.time()

	def get_domain_info(self, domain: str, page: int = 1, include_map: bool = False) -> Dict:
		"""
		Get comprehensive DNS and attack surface information for a domain.

		Args:
			domain: Domain name to scan
			page: Page number for pagination (requires Plus membership)
			include_map: Include domain map in response (requires Plus membership)

		Returns:
			Dictionary containing DNS records and attack surface data

		Raises:
			requests.HTTPError: If the API request fails
			ValueError: If response is invalid
		"""
		self._wait_for_rate_limit()

		url = f"{self.BASE_URL}/domain/{domain}"
		params = {}

		if page > 1:
			params['page'] = page

		if include_map:
			params['map'] = 1

		try:
			response = self.session.get(url, params=params, timeout=30, verify=False)
			response.raise_for_status()

			data = response.json()

			# Check for error in response
			if 'error' in data:
				raise ValueError(f"API Error: {data['error']}")

			return data

		except requests.exceptions.HTTPError as e:
			if e.response.status_code == 429:
				raise ValueError(
					"Rate limit exceeded. Please wait before making another request.") from e
			if e.response.status_code == 401:
				raise ValueError(
					"Invalid API key. Please check your DNSDumpster API key.") from e
			if e.response.status_code == 403:
				raise ValueError(
					"Access forbidden. Check your API key and membership level.") from e
			raise ValueError(
				f"HTTP Error {e.response.status_code}: {e.response.text}") from e

		except requests.exceptions.Timeout as exc:
			raise ValueError("Request timed out. Please try again.") from exc

		except requests.exceptions.RequestException as e:
			raise ValueError(f"Request failed: {str(e)}") from e

		except ValueError as e:
			if "JSON" in str(e):
				raise ValueError("Invalid JSON response from API") from e
			raise

	def parse_results(self, data: Dict) -> Dict:
		"""
		Parse DNSDumpster results into a standardized format.

		Args:
			data: Raw API response data

		Returns:
			Parsed and structured data
		"""
		parsed = {
			'a_records': [],
			'nameservers': [],
			'mx_records': [],
			'cname_records': [],
			'txt_records': [],
			'total_a_records': data.get('total_a_recs', 0)
		}

		# Parse A records
		if data.get('a'):
			parsed['a_records'] = data['a']

		# Parse nameservers
		if data.get('ns'):
			parsed['nameservers'] = data['ns']

		# Parse MX records
		if data.get('mx'):
			parsed['mx_records'] = data['mx']

		# Parse CNAME records
		if data.get('cname'):
			parsed['cname_records'] = data['cname']

		# Parse TXT records
		if data.get('txt'):
			parsed['txt_records'] = data['txt']

		return parsed

	def get_all_ips(self, parsed_data: Dict) -> list:
		"""
		Extract all unique IP addresses from parsed data.

		Args:
			parsed_data: Parsed DNSDumpster data

		Returns:
			List of unique IP addresses
		"""
		ips = set()

		# Extract from A records
		for record in parsed_data.get('a_records', []):
			for ip_info in record.get('ips', []):
				if ip_info.get('ip'):
					ips.add(ip_info['ip'])

		# Extract from nameservers
		for ns in parsed_data.get('nameservers', []):
			for ip_info in ns.get('ips', []):
				if ip_info.get('ip'):
					ips.add(ip_info['ip'])

		# Extract from MX records
		for mx in parsed_data.get('mx_records', []):
			for ip_info in mx.get('ips', []):
				if ip_info.get('ip'):
					ips.add(ip_info['ip'])

		return list(ips)

	def get_all_domains(self, parsed_data: Dict) -> list:
		"""
		Extract all unique domain/hostname from parsed data.

		Args:
			parsed_data: Parsed DNSDumpster data

		Returns:
			List of unique domains/hostnames
		"""
		domains = set()

		# Extract from A records
		for record in parsed_data.get('a_records', []):
			if record.get('host'):
				domains.add(record['host'])

		# Extract from nameservers
		for ns in parsed_data.get('nameservers', []):
			if ns.get('host'):
				domains.add(ns['host'])

		# Extract from MX records
		for mx in parsed_data.get('mx_records', []):
			if mx.get('host'):
				domains.add(mx['host'])

		# Extract from CNAME records
		for cname in parsed_data.get('cname_records', []):
			if cname.get('host'):
				domains.add(cname['host'])
			if cname.get('target'):
				domains.add(cname['target'])

		return list(domains)
		