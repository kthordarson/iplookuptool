from loguru import logger
import os
import aiohttp
import asyncio

async def get_alienvault_data(args):
    data = []
    ALIENTVAULTAPIKEY = os.environ.get("ALIENTVAULTAPIKEY")
    if not ALIENTVAULTAPIKEY:
        logger.warning("missing alienvault api key")
        return data
    if args.ip:
        iplist = [args.ip]
    else:
        iplist = args.ips
    headers = {"x-api-key": ALIENTVAULTAPIKEY}
    for ipaddr_ in iplist:
        ipaddr = ''.join(ipaddr_)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ipaddr}", headers=headers, ssl=False) as response:
                    if response.status == 200:
                        try:
                            jsonresp = await response.json()
                        except Exception as e:
                            logger.error(f"[!] {e} {type(e)} while parsing json response")
                            await asyncio.sleep(1)
                            continue
                        if jsonresp:
                            data.append(jsonresp)
                        else:
                            logger.error(f"Unknown error for {args.ip} json: {jsonresp}")
                            await asyncio.sleep(1)
                            continue
                    elif response.status in [502, 503, 504]:
                        logger.warning(f"[!] {response.status} {response.reason} for {ipaddr}")
                        await asyncio.sleep(1)
                        continue
                    elif response.status == 404:
                        if args.debug:
                            text = await response.text()
                            logger.warning(f"[!] not found {args.ip} {text}")  # type: ignore
                        await asyncio.sleep(1)
                        continue
                    else:
                        logger.warning(f"[!] {response.status} {response.reason} for {ipaddr}")
                        if args.debug:
                            logger.warning(f"headers: {response.headers}")
                            logger.warning(f"text: {await response.text()}")
                        await asyncio.sleep(1)
                        continue
        except Exception as e:
            logger.error(f"[!] {e} {type(e)}")
    return data
