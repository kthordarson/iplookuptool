import asyncio
import json

import aiohttp
from loguru import logger

# curl 'https://rdap.arin.net/registry/autnum/16509'   -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0'   -H 'Accept: */*'   -H 'Accept-Language: en-US,en;q=0.9'   -H 'Accept-Encoding: gzip, deflate, br, zstd'   -H 'Origin: null'   -H 'Referer: https://search.arin.net/'   -H 'DNT: 1'   -H 'Connection: keep-alive'   -H 'Sec-Fetch-Dest: empty'   -H 'Sec-Fetch-Mode: cors'   -H 'Sec-Fetch-Site: same-site'   -H 'Priority: u=0'   -H 'Pragma: no-cache'   -H 'Cache-Control: no-cache'
# curl 'https://rdap.db.ripe.net/ip/51.92.249.166'    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0'    -H 'Accept: */*'    -H 'Accept-Language: en-US,en;q=0.9'    -H 'Accept-Encoding: gzip, deflate, br, zstd'    -H 'Origin: null'    -H 'Referer: https://search.arin.net/'    -H 'DNT: 1'    -H 'Connection: keep-alive'    -H 'Sec-Fetch-Dest: empty'    -H 'Sec-Fetch-Mode: cors'    -H 'Sec-Fetch-Site: cross-site'    -H 'Priority: u=0'    -H 'Pragma: no-cache'    -H 'Cache-Control: no-cache'    -H 'TE: trailers'
# curl -sL ip.guide/as16509

async def get_ripe_info(ip) -> dict:
    url = f"https://rdap.db.ripe.net/ip/{ip}"
    headers = {"accept": "application/json"}
    try:
        async with aiohttp.ClientSession() as session, session.get(url, headers=headers) as response:
            jsonresults = await response.json()
            return jsonresults
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
        logger.error(f"[!] {e} {type(e)} addr: {ip}")
        return {}

async def get_arin_as_info(asn) -> dict:
    if asn.lower().startswith("as"):
        asn = asn[2:]
    url = f"https://rdap.arin.net/registry/autnum/{asn}"
    headers = {"accept": "application/json"}
    try:
        async with aiohttp.ClientSession() as session, session.get(url, headers=headers) as response:
            jsonresults = await response.json()
            return jsonresults
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
        logger.error(f"[!] {e} {type(e)} asn: {asn}")
        return {}
    
async def get_ipguide_info(asn: str) -> dict:
    asn = asn.lower()
    if asn.startswith("as"):        
        url = f"https://ip.guide/{asn}"
    else:
        url = f"https://ip.guide/as{asn}"
    headers = {"accept": "application/json"}
    try:
        async with aiohttp.ClientSession() as session, session.get(url, headers=headers) as response:
            info = await response.text()
            json_info = json.loads(info)
            return json_info
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
        logger.error(f"[!] {e} {type(e)} asn: {asn}")
        return {}
    
