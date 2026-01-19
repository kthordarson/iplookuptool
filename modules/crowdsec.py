from loguru import logger
import os
import aiohttp
import asyncio

async def get_crowdsec_data(args):
    CROWDSECAPIKEY = os.environ.get("CROWDSECAPIKEY")
    if not CROWDSECAPIKEY:
        logger.warning("missing crowdsec api key")
        return None
    headers = {"x-api-key": CROWDSECAPIKEY}
    if args.ip:
        iplist = [args.ip]
    else:
        iplist = args.ips
    data = []
    try:
        for ipaddr_ in iplist:
            ipaddr = ''.join(ipaddr_)
            # logger.debug(f"querying crowdsec for {ipaddr} {ipaddr_}")
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://cti.api.crowdsec.net/v2/smoke/{ipaddr}", headers=headers, ssl=False) as response:
                    if response.status == 200:
                        try:
                            jsonresp = await response.json()
                        except Exception as e:
                            logger.error(f"[!] {e} {type(e)} while parsing json response")
                            return None
                        if jsonresp:
                            data.append(jsonresp)
                        else:
                            logger.error(f"Unknown error for {ipaddr} json: {jsonresp}")
                            await asyncio.sleep(1)
                            continue
                    elif response.status == 404:
                        if args.debug:
                            text = await response.text()
                            logger.warning(f"[!] not found {ipaddr} {text}")  # type: ignore
                        await asyncio.sleep(1)
                        continue
                    else:
                        logger.warning(f"[!] {response.status} {response.reason} for {ipaddr}")
                        if args.debug:
                            responsetext = await response.text()
                            logger.warning(f"response: {responsetext}")
                        await asyncio.sleep(1)
                        continue
    except Exception as e:
        logger.error(f"[!] {e} {type(e)}")
    return data
